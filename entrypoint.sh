#!/bin/bash
# t-forward container entrypoint - runs ONE tunnel, of TUNNEL_TYPE:
#
#   vpn   : openconnect (SSL-VPN) OR strongSwan (IPsec/IKE) tunnel, then socat
#           forwards + optional SOCKS proxy. VPN_PROTOCOL=ipsec picks strongSwan
#           (FortiGate dialup: PSK + XAuth); anything else is openconnect.
#   ssh   : ssh -N tunnel with -L forwards + optional -D SOCKS proxy
#   local : plain socat forwards + optional SOCKS proxy (no tunnel at all)
#
# Contract with the host CLI:
#   /auth (mounted tmpdir, mode 700) may contain:
#     password     -> vpn: first stdin line for openconnect; ssh: sshpass file
#                     ipsec: XAuth password (written into ipsec.secrets)
#     psk          -> ipsec only: the IKE pre-shared key (ipsec.secrets)
#     totp_secret  -> vpn only: "base32:<SECRET>" enables automatic TOTP
#     ssh_key      -> ssh only: private key (copied in by the CLI, mode 600)
#     code         -> vpn only: written by the host when the user types the code
#   Files dropped by this script into /auth:
#     awaiting_code -> vpn only: tells the host to prompt the user for a code
#     ready         -> tunnel is up and all forwards/proxy are running
#
# Environment:
#   TUNNEL_TYPE                         vpn (default) | ssh | local
#   VPN_SERVER, VPN_PROTOCOL, VPN_USER  (vpn)
#   SERVERCERT, AUTHGROUP, TOTP, NO_DTLS (vpn openconnect, optional)
#   IKE_VERSION, IKE_PROPOSAL, ESP_PROPOSAL, IPSEC_IKELIFETIME, IPSEC_LIFETIME,
#     IPSEC_LOCALID, IPSEC_REMOTEID                (vpn ipsec, optional)
#   SSH_HOST, SSH_USER, SSH_PORT        (ssh; port defaults to 22)
#   SSH_JUMP="[user@]host[:port] ..."   (ssh; ordered ProxyJump hops to reach
#                                        SSH_HOST — needs key auth, not password)
#   FORWARDS="lport|rhost|rport;..."    (container-internal listen ports)
#   SOCKS=true|false                    (proxy on :1080)
#   KEEP_AUTH=true|false                (keep credentials for restart policy)
#   CONNECT_TIMEOUT                     (seconds to wait for the tunnel, default 60)

set -u

AUTH=/auth
PIPE=/run/authpipe
OC_LOG=/run/openconnect.log
TYPE="${TUNNEL_TYPE:-vpn}"
TUN_TIMEOUT="${CONNECT_TIMEOUT:-60}"
# How long a manual-TOTP container waits for the host to deliver the code. This
# is deliberately generous and independent of TUN_TIMEOUT: the code arrives by
# SMS/mail only after the password is submitted (often 1-2 min), then a human
# has to read and type it. Bounded only so an abandoned detached handoff (panel
# closed, host crashed) self-terminates instead of blocking forever.
CODE_TIMEOUT="${CODE_TIMEOUT:-600}"

log() { echo "[t-forward] $*"; }

fail() {
    log "ERROR: $*"
    exit 1
}

# Detect a credentials rejection in openconnect's mirrored output. Without
# this, a rejected password is indistinguishable from "still authenticating":
# openconnect silently re-prompts on stdin and blocks forever.
#   - explicit failure strings (gp answers 512 to a bad login, anyconnect
#     prints "Login failed", fortinet's error page says "Permission denied")
#   - a printed "Password:" prompt: with --passwd-on-stdin the first password
#     is consumed silently, so a visible prompt can only be a re-ask (fortinet)
auth_rejected() {
    [ -s "$OC_LOG" ] || return 1
    grep -qiE "login failed|authentication failed|permission denied|unexpected 512 result|access denied" "$OC_LOG" && return 0
    grep -qE "^Password:" "$OC_LOG"
}

# stale leftovers from a previous run of this container (restart policy)
rm -f "$AUTH/ready" "$AUTH/awaiting_code" "$AUTH/code" "$PIPE"

# Listeners bind to eth0 (the Docker-published side) only, so nothing on
# the far side of a tunnel can reach the forwards or the SOCKS proxy.
ETH_IP=$(ip -4 addr show eth0 | awk '/inet /{print $2}' | cut -d/ -f1)
[ -n "$ETH_IP" ] || fail "could not determine eth0 address"

start_socat_forwards() {
    local spec lport rhost rport
    [ -n "${FORWARDS:-}" ] || return 0
    IFS=';' read -ra specs <<<"$FORWARDS"
    for spec in "${specs[@]}"; do
        [ -n "$spec" ] || continue
        IFS='|' read -r lport rhost rport <<<"$spec"
        # -d -d makes socat log every accepted connection (source ip:port),
        # which the panel/daemon surface as connection events
        socat -d -d "TCP-LISTEN:${lport},bind=${ETH_IP},fork,reuseaddr" "TCP:${rhost}:${rport}" 2>&1 &
        log "forward: ${ETH_IP}:${lport} -> ${rhost}:${rport}"
    done
}

start_socks() {
    [ "${SOCKS:-false}" = "true" ] || return 0
    microsocks -i "$ETH_IP" -p 1080 &
    log "SOCKS5 proxy on ${ETH_IP}:1080"
}

mark_ready() {
    if [ "${KEEP_AUTH:-false}" != "true" ]; then
        rm -f "$AUTH/password" "$AUTH/totp_secret" "$AUTH/ssh_key" "$AUTH/code"
    fi
    touch "$AUTH/ready"
    log "READY"
}

port_listening() {
    ss -tln 2>/dev/null | grep -q ":$1 "
}

# --------------------------------------------------------------------- vpn

run_vpn() {
    [ -n "${VPN_SERVER:-}" ] || fail "VPN_SERVER is required"
    [ -n "${VPN_PROTOCOL:-}" ] || fail "VPN_PROTOCOL is required"
    [ -n "${VPN_USER:-}" ] || fail "VPN_USER is required"
    [ -s "$AUTH/password" ] || fail "/auth/password is missing"

    mkfifo "$PIPE"

    # No pinned servercert -> probe the server once to learn its current
    # certificate pin and trust it (Trust-On-First-Use). openconnect prints the
    # pin when the cert isn't already trusted; --non-inter makes it abort instead
    # of prompting. This avoids re-pinning by hand every time the VPN rotates its
    # cert, at the cost of MITM protection (same as accepting the cert manually).
    if [ -z "${SERVERCERT:-}" ]; then
        log "no servercert pinned; probing the server certificate…"
        SERVERCERT=$(timeout 25 openconnect --protocol="$VPN_PROTOCOL" "$VPN_SERVER" \
            --user="$VPN_USER" --non-inter </dev/null 2>&1 \
            | grep -oE 'pin-sha256:[A-Za-z0-9+/=]+' | head -1)
        if [ -n "$SERVERCERT" ]; then
            log "auto-detected servercert $SERVERCERT (not pre-pinned)"
            log "SECURITY: trust-on-first-use — this run trusts whatever certificate the"
            log "  server presented and CANNOT detect a first-connection MITM. Pin it in"
            log "  the config (vpn.servercert: $SERVERCERT) to close that window."
        else
            log "no pin printed (certificate is CA-trusted or probe failed)"
        fi
    fi

    local cmd=(openconnect --protocol="$VPN_PROTOCOL" "$VPN_SERVER"
               --user="$VPN_USER" --passwd-on-stdin --interface=tun0
               --reconnect-timeout 300)
    [ -n "${SERVERCERT:-}" ] && cmd+=(--servercert "$SERVERCERT")
    [ -n "${AUTHGROUP:-}" ] && cmd+=(--authgroup "$AUTHGROUP")
    # Some gateways half-break DTLS: the handshake succeeds but the in-tunnel
    # MTU probe is blackholed, stalling openconnect ~60s before it falls back
    # to SSL. no_dtls skips UDP entirely and tunnels over TLS from the start.
    [ "${NO_DTLS:-false}" = "true" ] && cmd+=(--no-dtls)
    if [ -s "$AUTH/totp_secret" ]; then
        cmd+=(--token-mode=totp --token-secret="@$AUTH/totp_secret")
    fi

    log "connecting to $VPN_SERVER (protocol: $VPN_PROTOCOL, user: $VPN_USER)"
    # Mirror openconnect's output into a file so the wait loops below can spot
    # an authentication rejection (which otherwise looks exactly like "still
    # waiting": openconnect just re-prompts on stdin and blocks).
    : > "$OC_LOG"
    "${cmd[@]}" <"$PIPE" > >(tee -a "$OC_LOG") 2> >(tee -a "$OC_LOG" >&2) &
    local oc_pid=$!

    # keep a writer fd open so openconnect doesn't see EOF between auth fields
    exec 3>"$PIPE"
    cat "$AUTH/password" >&3
    # The password is now consumed into the pipe; erase the on-disk plaintext
    # immediately (unless a restart policy needs it) so it does not linger while
    # we wait for a TOTP code -- a wait that, in detached (--no-prompt) mode, may
    # be abandoned by the host without ever calling mark_ready.
    [ "${KEEP_AUTH:-false}" = "true" ] || rm -f "$AUTH/password"

    if [ "${TOTP:-false}" = "true" ] && [ ! -s "$AUTH/totp_secret" ]; then
        touch "$AUTH/awaiting_code"
        log "password sent; waiting for verification code from the host"
        # Bound the wait so an abandoned detached handoff (host crashed / never
        # ran `t-forward code`) self-terminates instead of blocking forever.
        local waited=0 max_wait="$CODE_TIMEOUT"
        while [ ! -s "$AUTH/code" ]; do
            kill -0 "$oc_pid" 2>/dev/null || fail "openconnect exited during authentication"
            auth_rejected && fail "the VPN rejected the credentials (wrong password?) — check vpn.password in the config"
            waited=$((waited + 1))
            [ "$waited" -ge "$max_wait" ] && fail "no verification code within ${max_wait}s; aborting"
            sleep 1
        done
        cat "$AUTH/code" >&3
        rm -f "$AUTH/code" "$AUTH/awaiting_code"
        log "verification code forwarded"
    fi
    exec 3>&-

    log "waiting for tunnel interface (max ${TUN_TIMEOUT}s)"
    local i=0
    while ! ip -4 addr show tun0 2>/dev/null | grep -q inet; do
        kill -0 "$oc_pid" 2>/dev/null || fail "openconnect exited (authentication failed?)"
        auth_rejected && fail "the VPN rejected the credentials (wrong password?) — check vpn.password in the config"
        i=$((i + 1))
        [ "$i" -ge "$TUN_TIMEOUT" ] && fail "tunnel did not come up within ${TUN_TIMEOUT}s"
        sleep 1
    done
    log "tunnel is up: tun0 $(ip -4 addr show tun0 | awk '/inet /{print $2}' | cut -d/ -f1)"

    start_socat_forwards
    start_socks
    mark_ready

    wait "$oc_pid"
    local rc=$?
    log "openconnect exited with status $rc"
    exit "$rc"
}

# ------------------------------------------------------------------- ipsec

# strongSwan (charon) IKE/IPsec tunnel — FortiGate "dialup" style: IKEv1 (or v2)
# with a pre-shared key for the IKE SA plus XAuth (user/password) for the user,
# and mode-config (leftsourceip=%config) to get a virtual IP. No tun0: charon
# installs XFRM policies + a route (table 220) so packets to the remote hosts
# are encrypted transparently, and the existing socat forwards work unchanged.
run_ipsec() {
    [ -n "${VPN_SERVER:-}" ] || fail "VPN_SERVER is required"
    [ -n "${VPN_USER:-}" ]   || fail "VPN_USER is required (XAuth user)"
    [ -s "$AUTH/password" ]  || fail "/auth/password is missing (XAuth password)"
    [ -s "$AUTH/psk" ]       || fail "/auth/psk is missing (IKE pre-shared key)"

    local ikev="${IKE_VERSION:-1}"
    local aggressive=no
    # IKEv1 FortiGate dialup normally negotiates in aggressive mode (the group
    # name travels as the ID in the first packet); IKEv2 has no aggressive mode.
    [ "$ikev" = "1" ] && aggressive=yes

    # Proposals default to the FortiGate defaults seen in the wild (P1: AES256/
    # SHA256/DH14, P2: AES256/SHA256 + PFS DH5). Override per-tunnel if the
    # gateway is pickier — a mismatch shows as NO_PROPOSAL_CHOSEN in the log.
    local ike_prop="${IKE_PROPOSAL:-aes256-sha256-modp2048,aes128-sha256-modp2048}"
    local esp_prop="${ESP_PROPOSAL:-aes256-sha256-modp1536,aes128-sha256-modp1536}"

    # XAuth password: FortiToken 2FA appends the one-time code to the password.
    # If TOTP is on we wait for the host to deliver the code (same handoff as the
    # openconnect path) and concatenate it, matching the FortiClient behaviour.
    local xpass; xpass=$(cat "$AUTH/password")
    if [ "${TOTP:-false}" = "true" ] && [ ! -s "$AUTH/totp_secret" ]; then
        touch "$AUTH/awaiting_code"
        log "XAuth password set; waiting for verification code from the host"
        local waited=0 max_wait="$CODE_TIMEOUT"
        while [ ! -s "$AUTH/code" ]; do
            waited=$((waited + 1))
            [ "$waited" -ge "$max_wait" ] && fail "no verification code within ${max_wait}s; aborting"
            sleep 1
        done
        xpass="${xpass}$(cat "$AUTH/code")"
        rm -f "$AUTH/code" "$AUTH/awaiting_code"
        log "verification code appended to XAuth password"
    elif [ -s "$AUTH/totp_secret" ]; then
        # base32:SECRET -> generate the current TOTP and append it, no host round-trip
        local secret; secret=$(sed 's/^base32://' "$AUTH/totp_secret")
        local otp; otp=$(oathtool --totp -b "$secret" 2>/dev/null) \
            && [ -n "$otp" ] && xpass="${xpass}${otp}" \
            && log "generated TOTP appended to XAuth password"
    fi

    # leftid: the Local ID / peer-ID the gateway expects (often the group name).
    # Empty is fine for most FortiGate dialups (they key on the PSK).
    local leftid_line="" rightid_line=""
    [ -n "${IPSEC_LOCALID:-}" ]  && leftid_line="    leftid=${IPSEC_LOCALID}"
    [ -n "${IPSEC_REMOTEID:-}" ] && rightid_line="    rightid=${IPSEC_REMOTEID}"

    # ipsec.secrets: the PSK (IKE) and the XAuth credential. 0600, root-only.
    umask 077
    {
        printf ': PSK "%s"\n' "$(cat "$AUTH/psk")"
        printf '%s : XAUTH "%s"\n' "$VPN_USER" "$xpass"
    } > /etc/ipsec.secrets
    # psk on disk is now in ipsec.secrets only; drop the mounted copy unless a
    # restart policy needs it to reconnect after a crash.
    [ "${KEEP_AUTH:-false}" = "true" ] || rm -f "$AUTH/psk" "$AUTH/password"

    cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 1, cfg 1, knl 1"

conn tforward
    keyexchange=ikev${ikev}
    aggressive=${aggressive}
    authby=xauthpsk
    xauth=client
    left=%defaultroute
    leftsourceip=%config
    leftauth=psk
    leftauth2=xauth
${leftid_line}
    right=${VPN_SERVER}
    rightauth=psk
    rightsubnet=0.0.0.0/0
${rightid_line}
    xauth_identity=${VPN_USER}
    ike=${ike_prop}!
    esp=${esp_prop}!
    ikelifetime=${IPSEC_IKELIFETIME:-28800s}
    lifetime=${IPSEC_LIFETIME:-43200s}
    dpddelay=30s
    dpdaction=restart
    closeaction=restart
    auto=start
EOF

    log "connecting to $VPN_SERVER (protocol: ipsec/ikev${ikev}, user: $VPN_USER)"

    # charon writes to syslog; in a container there is no syslogd, so run the
    # starter in nofork+stderr mode and mirror it into OC_LOG for the wait loop.
    : > "$OC_LOG"
    ipsec start --nofork > >(tee -a "$OC_LOG") 2>&1 &
    local ipsec_pid=$!

    # Wait for the CHILD_SA to install. The legacy starter reports it as
    # "ESTABLISHED"/"INSTALLED"; a rejected XAuth/PSK shows as XAUTH failed or
    # NO_PROPOSAL_CHOSEN in the mirrored log, which we surface instead of hanging.
    log "waiting for IPsec SA (max ${TUN_TIMEOUT}s)"
    local i=0 up=""
    while [ -z "$up" ]; do
        kill -0 "$ipsec_pid" 2>/dev/null || fail "charon exited during negotiation"
        if grep -qiE 'XAUTH authentication failed|AUTHENTICATION_FAILED|authentication failed|INVALID_ID_INFORMATION' "$OC_LOG"; then
            fail "the VPN rejected the credentials (XAuth/PSK) — check vpn.psk / vpn.user / vpn.password"
        fi
        if grep -qi 'NO_PROPOSAL_CHOSEN' "$OC_LOG"; then
            fail "no matching proposal — set vpn.ike_proposal / vpn.esp_proposal to the gateway's Phase1/Phase2 algorithms"
        fi
        # CHILD_SA up: either the starter status or a mirrored "established/INSTALLED"
        if ipsec status 2>/dev/null | grep -qE 'INSTALLED|ESTABLISHED' \
           || grep -qiE 'CHILD_SA .* (established|INSTALLED)' "$OC_LOG"; then
            up=1; break
        fi
        i=$((i + 1))
        [ "$i" -ge "$TUN_TIMEOUT" ] && fail "IPsec tunnel did not come up within ${TUN_TIMEOUT}s"
        sleep 1
    done

    local vip; vip=$(ip -4 addr show 2>/dev/null | awk '/inet /{print $2}' | grep -vE '^(127\.|'"${ETH_IP%.*}"'\.)' | cut -d/ -f1 | head -1)
    log "IPsec tunnel is up${vip:+ (virtual IP $vip)}"

    start_socat_forwards
    start_socks
    mark_ready

    wait "$ipsec_pid"
    local rc=$?
    log "charon exited with status $rc"
    exit "$rc"
}

# --------------------------------------------------------------------- ssh

run_ssh() {
    [ -n "${SSH_HOST:-}" ] || fail "SSH_HOST is required"
    [ -n "${SSH_USER:-}" ] || fail "SSH_USER is required"
    [ -s "$AUTH/ssh_key" ] || [ -s "$AUTH/password" ] \
        || fail "ssh needs /auth/ssh_key or /auth/password"

    # StrictHostKeyChecking=accept-new trusts an unseen host key on first contact
    # (trust-on-first-use): convenient, but the first connection cannot detect a
    # MITM. The known_hosts file is per-run (under /auth), so every fresh tunnel is
    # a first connection. Pre-seed /auth/known_hosts (or pin the key out of band)
    # for sensitive hosts to close that window.
    local args=(-N -p "${SSH_PORT:-22}"
                -o ExitOnForwardFailure=yes
                -o ServerAliveInterval=15 -o ServerAliveCountMax=3
                -o StrictHostKeyChecking=accept-new
                -o UserKnownHostsFile="$AUTH/known_hosts")
    [ -s "$AUTH/ssh_key" ] && args+=(-i "$AUTH/ssh_key" -o IdentitiesOnly=yes)

    # multi-hop: chain through one or more jump hosts to reach SSH_HOST. ssh's
    # ProxyJump (-J) applies the same key/known-hosts options to every hop, so
    # this only works with key auth (sshpass can feed a password to the first
    # hop only). Each hop is "[user@]host[:port]"; user/port default to the
    # tunnel's SSH_USER / 22.
    if [ -n "${SSH_JUMP:-}" ]; then
        [ -s "$AUTH/ssh_key" ] \
            || fail "SSH_JUMP (multi-hop) needs key auth (/auth/ssh_key), not a password"
        local jhops=() hop hu hh hp
        set -f   # split the hop list on whitespace, but never glob a hop token
        for hop in $(printf '%s' "$SSH_JUMP" | tr ',' ' '); do
            [ -n "$hop" ] || continue
            hu=$SSH_USER hh=$hop hp=22
            case "$hh" in *@*) hu=${hh%%@*}; hh=${hh#*@} ;; esac
            case "$hh" in *:*) hp=${hh##*:}; hh=${hh%:*} ;; esac
            jhops+=("${hu}@${hh}:${hp}")
        done
        set +f
        if [ "${#jhops[@]}" -gt 0 ]; then
            local oldIFS=$IFS; IFS=,
            args+=(-J "${jhops[*]}")
            IFS=$oldIFS
            log "jump chain: ${jhops[*]} -> ${SSH_HOST}"
        fi
    fi

    local probe="" spec lport rhost rport
    if [ -n "${FORWARDS:-}" ]; then
        IFS=';' read -ra specs <<<"$FORWARDS"
        for spec in "${specs[@]}"; do
            [ -n "$spec" ] || continue
            IFS='|' read -r lport rhost rport <<<"$spec"
            args+=(-L "${ETH_IP}:${lport}:${rhost}:${rport}")
            log "forward: ${ETH_IP}:${lport} -> ${rhost}:${rport} (via ssh)"
            [ -n "$probe" ] || probe=$lport
        done
    fi
    if [ "${SOCKS:-false}" = "true" ]; then
        args+=(-D "${ETH_IP}:1080")
        log "SOCKS5 (ssh -D) on ${ETH_IP}:1080"
        [ -n "$probe" ] || probe=1080
    fi

    log "connecting to ${SSH_USER}@${SSH_HOST}:${SSH_PORT:-22}"
    local ssh_pid
    if [ -s "$AUTH/ssh_key" ]; then
        ssh -o BatchMode=yes "${args[@]}" "${SSH_USER}@${SSH_HOST}" &
        ssh_pid=$!
    else
        sshpass -f "$AUTH/password" ssh "${args[@]}" "${SSH_USER}@${SSH_HOST}" &
        ssh_pid=$!
    fi

    # ssh binds its -L/-D listeners only after successful authentication
    local i=0
    while [ -n "$probe" ] && ! port_listening "$probe"; do
        kill -0 "$ssh_pid" 2>/dev/null || fail "ssh exited (authentication failed?)"
        i=$((i + 1))
        [ "$i" -ge "$TUN_TIMEOUT" ] && fail "ssh did not come up within ${TUN_TIMEOUT}s"
        sleep 1
    done

    mark_ready

    wait "$ssh_pid"
    local rc=$?
    log "ssh exited with status $rc"
    exit "$rc"
}

# ------------------------------------------------------------------- local

run_local() {
    [ -n "${FORWARDS:-}" ] || [ "${SOCKS:-false}" = "true" ] \
        || fail "local tunnel needs FORWARDS and/or SOCKS"

    start_socat_forwards
    start_socks
    mark_ready

    # relays run as children; keep PID 1 alive
    while :; do sleep 3600; done
}

case "$TYPE" in
    vpn)   [ "${VPN_PROTOCOL:-}" = "ipsec" ] && run_ipsec || run_vpn ;;
    ssh)   run_ssh ;;
    local) run_local ;;
    *)     fail "unsupported TUNNEL_TYPE '$TYPE'" ;;
esac
