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
# Privileges:
#   The image runs as the unprivileged user tforward (uid 10001). ssh and local
#   need nothing more. vpn (openconnect / strongSwan) must create tun0 / XFRM
#   state and routes, so the host CLI starts it with `--user 0 --cap-add
#   NET_ADMIN --device /dev/net/tun` (see README "Privileges").
#
# Environment:
#   TUNNEL_TYPE                         vpn (default) | ssh | local
#   VPN_SERVER, VPN_PROTOCOL, VPN_USER  (vpn)
#   SERVERCERT, SERVERCERT_TOFU, AUTHGROUP, TOTP, NO_DTLS (vpn openconnect, optional)
#   IKE_VERSION, IKE_PROPOSAL, ESP_PROPOSAL, IPSEC_IKELIFETIME, IPSEC_LIFETIME,
#     IPSEC_LOCALID, IPSEC_REMOTEID                (vpn ipsec, optional)
#   SSH_HOST, SSH_USER, SSH_PORT        (ssh; port defaults to 22)
#   SSH_STRICT_HOST_KEY=true|false      (ssh; refuse a never-seen host key)
#   SSH_JUMP="[user@]host[:port] ..."   (ssh; ordered ProxyJump hops to reach
#                                        SSH_HOST — needs key auth, not password)
#   FORWARDS="lport|rhost|rport;..."    (container-internal listen ports)
#   SOCKS=true|false                    (proxy on :1080)
#   KEEP_AUTH=true|false                (keep credentials for restart policy)
#   CONNECT_TIMEOUT                     (seconds to wait for the tunnel, default 60)

set -u

AUTH=/auth
# private (700) scratch dir owned by the running user: ssh refuses keys that are
# group/world readable or owned by someone else, and /auth is a host bind mount
# whose ownership/permissions we do not control (Linux hosts).
PRIV_DIR="${HOME:-/tmp}/.tforward"
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

# openconnect refused the gateway certificate (not CA-trusted, or it does not
# match the pin). It then asks "accept?" on stdin, which is our password pipe,
# so without this check the failure looks like a generic auth problem.
cert_rejected() {
    [ -s "$OC_LOG" ] || return 1
    grep -qiE "failed verification|enter 'yes' to accept|specified via --servercert match" "$OC_LOG"
}

fail_cert_rejected() {
    local seen
    seen=$(grep -oE "server's certificate: pin-sha256:[A-Za-z0-9+/=]+" "$OC_LOG" 2>/dev/null | head -1 | sed 's/^server.s certificate: //')
    if [ -n "${SERVERCERT:-}" ]; then
        fail "the server certificate does not match the pinned vpn.servercert (pinned $SERVERCERT${seen:+, server presented $seen}). If the gateway legitimately changed its certificate, update vpn.servercert (or delete the stored pin of a vpn.tofu tunnel: pins/<name> in the config dir); otherwise this may be a man-in-the-middle."
    fi
    fail "the server certificate is not trusted by a public CA. For a gateway with a self-signed or private-CA certificate set vpn.servercert (pin-sha256:...), or opt in to trust-on-first-use with vpn.tofu: true."
}

# vpn needs root (tun0 / XFRM / routes); say so plainly instead of failing later
# with an obscure openconnect/charon error when run as the default user.
if [ "$TYPE" = "vpn" ] && [ "$(id -u)" != "0" ]; then
    fail "vpn mode needs root: run with --user 0 --cap-add NET_ADMIN --device /dev/net/tun (the t-forward CLI does this)"
fi
# every mode drops marker files into /auth; fail early when it is not writable
[ -d "$AUTH" ] && [ -w "$AUTH" ] \
    || fail "$AUTH is missing or not writable by uid $(id -u) (mount the auth dir there)"

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
        rm -f "$AUTH/password" "$AUTH/totp_secret" "$AUTH/ssh_key" "$AUTH/code" \
              "$PRIV_DIR/ssh_key"
    fi
    touch "$AUTH/ready"
    log "READY"
}

port_listening() {
    ss -tln 2>/dev/null | grep -q ":$1 "
}

# --------------------------------------------------------------------- vpn

# ipsec_field_ok NAME VALUE ERE - fail unless VALUE matches the whole-value ERE.
# An empty value is fine only when the ERE allows it.
ipsec_field_ok() {
    printf '%s' "$2" | LC_ALL=C grep -Eq -- "$3" 2>/dev/null && [[ "$2" != *[[:cntrl:]]* ]] \
        || fail "invalid $1 for ipsec (control characters, quotes or an unexpected format are not allowed)"
}

# ipsec_quote LABEL SECRET -> IPSEC_QUOTED. strongSwan reads "..." or '...' with
# no escape sequences, so pick the delimiter the secret does not contain.
ipsec_quote() {
    [[ "$2" != *[[:cntrl:]]* ]] || fail "$1 contains a line break or control character"
    case "$2" in
        *\"*) case "$2" in
                  *\'*) fail "$1 contains both ' and \" which ipsec.secrets cannot represent" ;;
              esac
              IPSEC_QUOTED="'$2'" ;;
        *)    IPSEC_QUOTED="\"$2\"" ;;
    esac
}

run_vpn() {
    [ -n "${VPN_SERVER:-}" ] || fail "VPN_SERVER is required"
    [ -n "${VPN_PROTOCOL:-}" ] || fail "VPN_PROTOCOL is required"
    [ -n "${VPN_USER:-}" ] || fail "VPN_USER is required"
    [ -s "$AUTH/password" ] || fail "/auth/password is missing"

    mkfifo "$PIPE"

    # Server identity. By default openconnect verifies the gateway certificate
    # against the system CA store and refuses anything else - an attacker on the
    # path cannot get a self-signed certificate accepted, so the password is
    # never sent to them. A gateway with a self-signed / private-CA certificate
    # needs one of:
    #   - SERVERCERT (vpn.servercert): an explicit pin-sha256 (also the stored pin
    #     the host CLI passes in after a TOFU run), enforced on every connect;
    #   - SERVERCERT_TOFU=true (vpn.tofu): opt-in trust-on-first-use. The first
    #     connection learns the pin and hands it to the host (learned_servercert);
    #     the CLI stores it outside the auth dir and passes it back as SERVERCERT
    #     from then on, so a changed certificate is rejected, not re-trusted.
    #
    # In restart mode the container is started again with the same env (no
    # SERVERCERT yet) and the auth dir survives, so a pin learned by an earlier
    # start is picked up from $AUTH/learned_servercert and enforced instead of
    # probing again - otherwise every restart would re-trust whatever the
    # network presents.
    if [ -z "${SERVERCERT:-}" ] && [ "${SERVERCERT_TOFU:-false}" = "true" ] \
        && [ ! -L "$AUTH/learned_servercert" ] && [ -s "$AUTH/learned_servercert" ]; then
        local learned
        learned=$(head -n 1 "$AUTH/learned_servercert")
        if [[ "$learned" =~ ^pin-sha256:[A-Za-z0-9+/=]+$ ]]; then
            SERVERCERT="$learned"
            log "tofu: enforcing the pin learned earlier ($SERVERCERT); a changed certificate is rejected"
        fi
    fi
    if [ -z "${SERVERCERT:-}" ] && [ "${SERVERCERT_TOFU:-false}" = "true" ]; then
        log "tofu: no servercert pinned yet; learning the server certificate pin…"
        SERVERCERT=$(timeout 25 openconnect --protocol="$VPN_PROTOCOL" "$VPN_SERVER" \
            --user="$VPN_USER" --non-inter </dev/null 2>&1 \
            | grep -oE 'pin-sha256:[A-Za-z0-9+/=]+' | head -1)
        if [ -n "$SERVERCERT" ]; then
            log "SECURITY: trust-on-first-use - trusting $SERVERCERT for this and later"
            log "  connections. This first connection cannot detect a MITM; verify the pin"
            log "  out of band, or set it as vpn.servercert in the config."
            ( umask 077; printf '%s\n' "$SERVERCERT" > "$AUTH/learned_servercert" )
        else
            log "tofu: no pin printed (the certificate is CA-trusted, or the probe failed)"
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
            cert_rejected && fail_cert_rejected
            kill -0 "$oc_pid" 2>/dev/null || { sleep 1; cert_rejected && fail_cert_rejected; fail "openconnect exited during authentication"; }
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
        cert_rejected && fail_cert_rejected
        kill -0 "$oc_pid" 2>/dev/null || { sleep 1; cert_rejected && fail_cert_rejected; fail "openconnect exited (authentication failed?)"; }
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

    # ipsec.conf / ipsec.secrets are line-oriented: a value with a line break would
    # add its own directive (e.g. leftupdown=<command>, which charon runs as
    # root). Everything interpolated below is checked first.
    ipsec_field_ok VPN_SERVER "$VPN_SERVER" '^[^[:cntrl:]"[:space:]]+$'
    ipsec_field_ok VPN_USER "$VPN_USER" '^[^[:cntrl:]"]+$'
    [ -z "${IPSEC_LOCALID:-}" ] || ipsec_field_ok IPSEC_LOCALID "$IPSEC_LOCALID" '^[^[:cntrl:]"]+$'
    [ -z "${IPSEC_REMOTEID:-}" ] || ipsec_field_ok IPSEC_REMOTEID "$IPSEC_REMOTEID" '^[^[:cntrl:]"]+$'
    ipsec_field_ok IKE_VERSION "$ikev" '^[12]$'
    ipsec_field_ok IKE_PROPOSAL "$ike_prop" '^[A-Za-z0-9_,-]+$'
    ipsec_field_ok ESP_PROPOSAL "$esp_prop" '^[A-Za-z0-9_,-]+$'
    ipsec_field_ok IPSEC_IKELIFETIME "${IPSEC_IKELIFETIME:-28800s}" '^[0-9]+[smhd]?$'
    ipsec_field_ok IPSEC_LIFETIME "${IPSEC_LIFETIME:-43200s}" '^[0-9]+[smhd]?$'
    local psk_q xpass_q
    ipsec_quote PSK "$(cat "$AUTH/psk")"; psk_q=$IPSEC_QUOTED
    ipsec_quote "XAuth password" "$xpass"; xpass_q=$IPSEC_QUOTED

    # leftid: the Local ID / peer-ID the gateway expects (often the group name).
    # Empty is fine for most FortiGate dialups (they key on the PSK).
    local leftid_line="" rightid_line=""
    [ -n "${IPSEC_LOCALID:-}" ]  && leftid_line="    leftid=${IPSEC_LOCALID}"
    [ -n "${IPSEC_REMOTEID:-}" ] && rightid_line="    rightid=${IPSEC_REMOTEID}"

    # ipsec.secrets: the PSK (IKE) and the XAuth credential. 0600, root-only.
    umask 077
    {
        printf ': PSK %s\n' "$psk_q"
        printf '%s : XAUTH %s\n' "$VPN_USER" "$xpass_q"
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

    # The key is copied to a private 0600 copy owned by the running user: ssh
    # refuses keys that are group/world readable, and /auth is a host bind mount
    # whose ownership/permissions we do not control (Linux hosts).
    # known_hosts is NOT copied: it stays in /auth so the pinned host key survives
    # a container restart (--restart) - otherwise every reconnect would be a new
    # trust-on-first-use.
    ( umask 077; mkdir -p "$PRIV_DIR" ) || fail "cannot create $PRIV_DIR"
    chmod 700 "$PRIV_DIR"
    if [ -s "$AUTH/ssh_key" ]; then
        ( umask 077; cat "$AUTH/ssh_key" > "$PRIV_DIR/ssh_key" ) \
            || fail "cannot read $AUTH/ssh_key"
        chmod 600 "$PRIV_DIR/ssh_key"
    fi

    # Host key verification. The host CLI seeds /auth/known_hosts from its
    # persistent store (outside the auth dir, so it survives every `up`) and
    # saves it back once the tunnel is up. StrictHostKeyChecking=accept-new
    # trusts a host key only the FIRST time it is ever seen; afterwards a changed
    # key is refused (ssh exits), also across restarts of a --restart tunnel.
    # SSH_STRICT_HOST_KEY=true (ssh.strict_host_key) drops even that first-use
    # trust: the key must already be in known_hosts (pre-seed it out of band).
    local hkc=accept-new
    if [ "${SSH_STRICT_HOST_KEY:-false}" = "true" ]; then
        hkc=yes
        [ -s "$AUTH/known_hosts" ] \
            || fail "ssh.strict_host_key is on but no known host key is stored for this tunnel: add the server's key to known_hosts/<name> in the config dir (ssh-keyscan -p PORT HOST), or turn strict_host_key off"
    fi
    local args=(-N -p "${SSH_PORT:-22}"
                -o ExitOnForwardFailure=yes
                -o ServerAliveInterval=15 -o ServerAliveCountMax=3
                -o StrictHostKeyChecking="$hkc"
                -o UserKnownHostsFile="$AUTH/known_hosts")
    [ -s "$PRIV_DIR/ssh_key" ] && args+=(-i "$PRIV_DIR/ssh_key" -o IdentitiesOnly=yes)

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
    local ssh_pid ssh_log="$PRIV_DIR/ssh.log"
    : > "$ssh_log"
    # stderr is mirrored into a file so a host-key refusal can be reported as such
    if [ -s "$AUTH/ssh_key" ]; then
        ssh -o BatchMode=yes "${args[@]}" "${SSH_USER}@${SSH_HOST}" 2> >(tee -a "$ssh_log" >&2) &
        ssh_pid=$!
    else
        sshpass -f "$AUTH/password" ssh "${args[@]}" "${SSH_USER}@${SSH_HOST}" 2> >(tee -a "$ssh_log" >&2) &
        ssh_pid=$!
    fi

    # ssh binds its -L/-D listeners only after successful authentication
    local i=0
    while [ -n "$probe" ] && ! port_listening "$probe"; do
        if ! kill -0 "$ssh_pid" 2>/dev/null; then
            sleep 1   # let the mirrored stderr land in the file
            if grep -qE "REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed" "$ssh_log"; then
                fail "the ssh host key for ${SSH_HOST} changed or is not trusted (see the ssh output above). If the server was legitimately rebuilt, remove its line from known_hosts/<name> in the config dir; otherwise this may be a man-in-the-middle."
            fi
            fail "ssh exited (authentication failed?)"
        fi
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
