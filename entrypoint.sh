#!/bin/bash
# t-forward container entrypoint - runs ONE tunnel, of TUNNEL_TYPE:
#
#   vpn   : openconnect tunnel, then socat forwards + optional SOCKS proxy
#   ssh   : ssh -N tunnel with -L forwards + optional -D SOCKS proxy
#   local : plain socat forwards + optional SOCKS proxy (no tunnel at all)
#
# Contract with the host CLI:
#   /auth (mounted tmpdir, mode 700) may contain:
#     password     -> vpn: first stdin line for openconnect; ssh: sshpass file
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
#   SERVERCERT, AUTHGROUP, TOTP         (vpn, optional)
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
TYPE="${TUNNEL_TYPE:-vpn}"
TUN_TIMEOUT="${CONNECT_TIMEOUT:-60}"

log() { echo "[t-forward] $*"; }

fail() {
    log "ERROR: $*"
    exit 1
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

    local cmd=(openconnect --protocol="$VPN_PROTOCOL" "$VPN_SERVER"
               --user="$VPN_USER" --passwd-on-stdin --interface=tun0
               --reconnect-timeout 300)
    [ -n "${SERVERCERT:-}" ] && cmd+=(--servercert "$SERVERCERT")
    [ -n "${AUTHGROUP:-}" ] && cmd+=(--authgroup "$AUTHGROUP")
    if [ -s "$AUTH/totp_secret" ]; then
        cmd+=(--token-mode=totp --token-secret="@$AUTH/totp_secret")
    fi

    log "connecting to $VPN_SERVER (protocol: $VPN_PROTOCOL, user: $VPN_USER)"
    "${cmd[@]}" <"$PIPE" &
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
        local waited=0 max_wait=$((TUN_TIMEOUT + 120))
        while [ ! -s "$AUTH/code" ]; do
            kill -0 "$oc_pid" 2>/dev/null || fail "openconnect exited during authentication"
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

# --------------------------------------------------------------------- ssh

run_ssh() {
    [ -n "${SSH_HOST:-}" ] || fail "SSH_HOST is required"
    [ -n "${SSH_USER:-}" ] || fail "SSH_USER is required"
    [ -s "$AUTH/ssh_key" ] || [ -s "$AUTH/password" ] \
        || fail "ssh needs /auth/ssh_key or /auth/password"

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
        for hop in $(printf '%s' "$SSH_JUMP" | tr ',' ' '); do
            [ -n "$hop" ] || continue
            hu=$SSH_USER hh=$hop hp=22
            case "$hh" in *@*) hu=${hh%%@*}; hh=${hh#*@} ;; esac
            case "$hh" in *:*) hp=${hh##*:}; hh=${hh%:*} ;; esac
            jhops+=("${hu}@${hh}:${hp}")
        done
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
    vpn)   run_vpn ;;
    ssh)   run_ssh ;;
    local) run_local ;;
    *)     fail "unsupported TUNNEL_TYPE '$TYPE'" ;;
esac
