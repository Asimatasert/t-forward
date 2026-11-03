#!/usr/bin/env bash
#
# Black-box tests for entrypoint.sh, the container entrypoint of t-forward.
#
#   bash tests/entrypoint/run.sh            run everything
#   bash tests/entrypoint/run.sh -v         also show stdout/stderr of failing tests
#
# No Docker, no root, no network, no bats: bash + coreutils + grep/sed/awk.
# The tunnel tools the entrypoint calls (openconnect, ipsec, ssh, sshpass, socat,
# microsocks, oathtool, ip, ss, id, sleep) are replaced by the fakes in
# tests/entrypoint/fake-bin, which sit first on a hermetic PATH, record every
# call (argument boundaries intact) and play the part of the real tool just far
# enough for the entrypoint to take each of its branches.
#
# entrypoint.sh itself runs unmodified except for ONE mechanical rewrite per
# test: the five absolute paths it hard-codes (/auth, /run/authpipe,
# /run/openconnect.log, /etc/ipsec.conf, /etc/ipsec.secrets) are redirected into
# the test's sandbox, so nothing outside `mktemp -d` is ever touched. The rewrite
# is checked (a drifted entrypoint makes the harness stop, exit 2) - no test
# hook exists in, or was added to, the script.
#
# Every test gets a fresh sandbox: auth dir, HOME, fake state, environment. The
# environment is `env -i` plus what the host CLI really passes (every variable
# of t-forward's `docker run -e ...` list, empty when unused).
#
# Not tested (needs root, a real network stack or real tunnel software):
#   - the real openconnect / strongSwan / ssh / socat / microsocks behaviour
#     (the fake output texts model the strings entrypoint.sh greps for; they were
#     not captured from a real gateway)
#   - tun0 / XFRM / route creation, eth0 detection on a real interface
#   - uid 0 vs uid 10001 file-permission effects inside the container
#   - PID-1 signal semantics (see tests/entrypoint "shutdown" scenarios: the
#     entrypoint is observed as an ordinary process; the PID-1 effect is argued
#     in the PR)
#   - the Dockerfile build and the image's installed packages (tests/tofu-restart.sh)
#
# Exit status: 0 = all green, 1 = failures, 2 = the harness itself cannot run.
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
EP=$ROOT/entrypoint.sh
FAKEBIN=$HERE/fake-bin
EXAMPLES=$ROOT/examples
VERBOSE=""
[ "${1:-}" = "-v" ] && VERBOSE=1

die_harness() { printf 'run.sh: %s\n' "$*" >&2; exit 2; }

[ -f "$EP" ] || die_harness "entrypoint not found: $EP"
[ -d "$FAKEBIN" ] || die_harness "fake-bin not found: $FAKEBIN"
[ -d "$EXAMPLES" ] || die_harness "examples not found: $EXAMPLES"
BASH_BIN=$(command -v bash)
REAL_SLEEP=$(command -v sleep)
[ -n "$BASH_BIN" ] && [ -n "$REAL_SLEEP" ] || die_harness "bash and sleep are required"
for f in "$FAKEBIN"/*; do
    case "$f" in */_common.sh) ;; *) [ -x "$f" ] || die_harness "fake is not executable: $f" ;; esac
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/tf-entrypoint-test.XXXXXX") || die_harness "mktemp failed"
EP_PID=""
cleanup() {
    [ -z "$EP_PID" ] || kill -KILL "$EP_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# ---- hermetic toolbox: the entrypoint sees only these tools + the fakes
CORE=$TMP/core; mkdir -p "$CORE"
for t in bash env sed tr grep cat head tail cut basename dirname mktemp rm mkdir chmod \
         stat cp mv find touch sort awk tee timeout mkfifo wc ls; do
    p=$(command -v "$t" 2>/dev/null)
    case "$p" in /*) ln -s "$p" "$CORE/$t" ;; *) die_harness "required tool missing: $t" ;; esac
done

# cap the runtime of a test that hangs (a regression in a wait loop)
ISOLATE=()
command -v timeout >/dev/null 2>&1 && ISOLATE+=(timeout -k 2 90)

# ------------------------------------------------------------------ framework
TESTS=0 ASSERTIONS=0 FAILS=0 CUR="" CUR_FAILED=0 SBN=0
SB="" RC=0 ENVV=() CALL=() DETAIL="" KILLED="" STDIN_FILE=""

flush_failure() {
    if [ "$CUR_FAILED" -eq 1 ] && [ -n "$VERBOSE" ] && [ -n "$SB" ]; then
        printf '       --- stdout ---\n'; sed 's/^/       /' "$SB/out" 2>/dev/null | head -n 25
        printf '       --- stderr ---\n'; sed 's/^/       /' "$SB/err" 2>/dev/null | head -n 15
    fi
}

# the variables the host CLI always passes with `docker run -e` (t-forward, "docker run -d")
CLI_BLANKS=(TUNNEL_TYPE= VPN_SERVER= VPN_PROTOCOL= VPN_USER= SERVERCERT= AUTHGROUP=
            TOTP=false NO_DTLS=false SERVERCERT_TOFU=false SSH_STRICT_HOST_KEY=false
            IKE_VERSION= IKE_PROPOSAL= ESP_PROPOSAL= IPSEC_LOCALID= IPSEC_REMOTEID=
            IPSEC_IKELIFETIME= IPSEC_LIFETIME= SSH_HOST= SSH_PORT= SSH_USER=
            SSH_JUMP= FORWARDS= SOCKS=false KEEP_AUTH=false)

begin() { # begin DESCRIPTION  -> fresh sandbox + a path-rewritten copy of entrypoint.sh
    flush_failure
    [ -z "$EP_PID" ] || { kill -KILL "$EP_PID" 2>/dev/null; EP_PID=""; }
    TESTS=$((TESTS + 1)); CUR=$1; CUR_FAILED=0; SBN=$((SBN + 1))
    SB=$TMP/sb$SBN; RC=0; KILLED=""; STDIN_FILE=""; DETAIL=""
    mkdir -p "$SB/auth" "$SB/run" "$SB/etc" "$SB/home" "$SB/state" "$SB/work"
    chmod 700 "$SB/auth"
    sed -e "s#^AUTH=/auth\$#AUTH=$SB/auth#" \
        -e "s#^PIPE=/run/authpipe\$#PIPE=$SB/run/authpipe#" \
        -e "s#^OC_LOG=/run/openconnect.log\$#OC_LOG=$SB/run/openconnect.log#" \
        -e "s#/etc/ipsec\\.#$SB/etc/ipsec.#g" "$EP" >"$SB/entrypoint.sh"
    # drift guard: every hard-coded system path must have been redirected
    grep -q "^AUTH=$SB/auth\$" "$SB/entrypoint.sh" \
        && grep -q "^PIPE=$SB/run/authpipe\$" "$SB/entrypoint.sh" \
        && grep -q "^OC_LOG=$SB/run/openconnect.log\$" "$SB/entrypoint.sh" \
        && grep -q "$SB/etc/ipsec.conf" "$SB/entrypoint.sh" \
        && grep -q "$SB/etc/ipsec.secrets" "$SB/entrypoint.sh" \
        || die_harness "entrypoint.sh no longer has the path assignments the harness redirects"
    if grep -vF "$SB" "$SB/entrypoint.sh" | grep -E '(^|[^A-Za-z0-9_])/(run|etc)/' | grep -vE '^[[:space:]]*#' >/dev/null; then
        die_harness "entrypoint.sh uses a new absolute /run or /etc path the harness does not redirect"
    fi
    ENVV=("PATH=$FAKEBIN:$CORE" "HOME=$SB/home" "FAKE_STATE=$SB/state"
          "FAKE_REAL_SLEEP=$REAL_SLEEP" LC_ALL=C TERM=dumb CONNECT_TIMEOUT=5
          "${CLI_BLANKS[@]}")
}

check() { # check DESCRIPTION COMMAND...   (the command's success = pass)
    local desc=$1; shift
    ASSERTIONS=$((ASSERTIONS + 1))
    DETAIL=""
    if "$@"; then return 0; fi
    FAILS=$((FAILS + 1))
    [ "$CUR_FAILED" -eq 1 ] || printf 'FAIL - %s\n' "$CUR"
    CUR_FAILED=1
    printf '       x %s%s\n' "$desc" "${DETAIL:+   [$DETAIL]}"
    return 1
}
not() { ! "$@"; }

E() { ENVV+=("$@"); }                       # add/override environment variables
authf() { printf '%s\n' "$2" >"$SB/auth/$1"; chmod "${3:-600}" "$SB/auth/$1"; }

# run to completion (bounded); sets RC, $SB/out, $SB/err
run_ep() {
    ( cd "$SB/work" && ${ISOLATE[@]+"${ISOLATE[@]}"} env -i "${ENVV[@]}" "$BASH_BIN" "$SB/entrypoint.sh" ) \
        <"${STDIN_FILE:-/dev/null}" >"$SB/out" 2>"$SB/err"
    RC=$?
}

# long-running tunnels: start in the background, drive from the test
start_ep() {
    ( cd "$SB/work" && exec env -i "${ENVV[@]}" "$BASH_BIN" "$SB/entrypoint.sh" ) \
        <"${STDIN_FILE:-/dev/null}" >"$SB/out" 2>"$SB/err" &
    EP_PID=$!
}
ep_alive() { kill -0 "$EP_PID" 2>/dev/null; }

# wait (max 15 s) for the ready marker, delivering the verification code when the
# entrypoint asks for one, exactly as the host CLI does (printf '%s\n' code > /auth/code)
settle() { # the relays are backgrounded: wait (max 3 s) until the recorded calls stop growing
    local i n m=-1 same=0
    for ((i = 0; i < 30 && same < 3; i++)); do
        n=$(n_calls_all)
        if [ "$n" = "$m" ]; then same=$((same + 1)); else same=0; fi
        m=$n
        "$REAL_SLEEP" 0.1
    done
}
await_ready() { # await_ready [CODE]
    local i
    for ((i = 0; i < 150; i++)); do
        if [ -e "$SB/auth/ready" ]; then settle; return 0; fi
        ep_alive || return 1
        if [ -e "$SB/auth/awaiting_code" ] && [ ! -e "$SB/auth/code" ]; then
            printf '%s\n' "${1:-123456}" >"$SB/auth/code"
        fi
        "$REAL_SLEEP" 0.1
    done
    return 1
}
await_file() { # await_file PATH  (max 15 s)
    local i
    for ((i = 0; i < 150; i++)); do
        [ -e "$1" ] && return 0
        ep_alive || return 1
        "$REAL_SLEEP" 0.1
    done
    return 1
}
finish_ep() { # wait (max 20 s) for the entrypoint to end by itself; sets RC
    local i
    for ((i = 0; i < 200; i++)); do ep_alive || break; "$REAL_SLEEP" 0.1; done
    if ep_alive; then KILLED=1; kill -KILL "$EP_PID" 2>/dev/null; fi
    wait "$EP_PID" 2>/dev/null; RC=$?
    EP_PID=""
}
stop_tunnel() { printf '%s' "${1:-0}" >"$SB/state/stop"; }   # end a healthy fake tunnel with status N
reset_state() { rm -rf "$SB/state"; mkdir -p "$SB/state"; }

# ---- assertions on the last run
rc()        { check "exit code is $1 (was $RC)" test "$RC" -eq "$1"; }
ended()     { check "the entrypoint ended on its own (did not hang)" test -z "$KILLED"; }
out_has()   { check "stdout has: $1" grep -qF -- "$1" "$SB/out"; }
out_lacks() { check "stdout lacks: $1" not grep -qF -- "$1" "$SB/out"; }
exists()    { check "exists: ${1#"$SB"/}" test -e "$1"; }
absent()    { check "absent: ${1#"$SB"/}" test ! -e "$1"; }
mode_is()   { check "mode of ${1#"$SB"/} is $2" test "$(stat -c %a "$1")" = "$2"; }
file_is()   { check "${1#"$SB"/} is exactly: $2" test "$(cat "$1" 2>/dev/null; echo x)" = "$2"$'\n'x; }
file_has()  { check "${1#"$SB"/} has: $2" grep -qxF -- "$2" "$1"; }
file_lacks() { check "${1#"$SB"/} lacks: $2" not grep -qF -- "$2" "$1"; }
state_has() { check "fake state $1 has: $2" grep -qxF -- "$2" "$SB/state/$1"; }

# ---- assertions on the recorded fake calls
load_call() { CALL=(); local a; while IFS= read -r -d '' a; do CALL+=("$a"); done <"$1"; }
call_file() { find "$SB/state/calls" -type f -name "*.$1" 2>/dev/null | sort | sed -n "${2}p"; }
call_n() { # call_n CMD N -> CALL = argv of the Nth call of CMD (CALL[0] is CMD); fails when absent
    local f; f=$(call_file "$1" "$2")
    [ -n "$f" ] || { CALL=(); return 1; }
    load_call "$f"
}
n_calls() { find "$SB/state/calls" -type f -name "*.$1" 2>/dev/null | wc -l; }
n_calls_all() { find "$SB/state/calls" -type f 2>/dev/null | wc -l; }
calls_are() { check "$1 was called $2 time(s) (was $(n_calls "$1"))" test "$(n_calls "$1")" -eq "$2"; }
no_calls()  { check "no tunnel command was called (was $(n_calls_all))" test "$(n_calls_all)" -eq 0; }
argv_is_()  { # argv_is_ CMD N ARG... -> the Nth call of CMD has exactly this argv
    local cmd=$1 n=$2 i; shift 2
    call_n "$cmd" "$n" || { DETAIL="no call #$n of $cmd"; return 1; }
    local want=("$cmd" "$@")
    DETAIL="got: ${CALL[*]}"
    [ "${#CALL[@]}" -eq "${#want[@]}" ] || return 1
    for ((i = 0; i < ${#want[@]}; i++)); do [ "${CALL[$i]}" = "${want[$i]}" ] || return 1; done
}
argv() { local cmd=$1 n=$2; shift 2; check "$cmd call #$n argv is: $*" argv_is_ "$cmd" "$n" "$@"; }
# The entrypoint starts its relays one after the other, but the processes are
# backgrounded, so which fake records first is up to the scheduler: for the
# relays (socat) the tests assert "some call has exactly this argv".
argv_any_() { # argv_any_ CMD ARG... -> one of the calls of CMD has exactly this argv
    local cmd=$1 f i seen=""; shift
    local want=("$cmd" "$@")
    while IFS= read -r f; do
        load_call "$f"
        seen+=" [${CALL[*]}]"
        [ "${#CALL[@]}" -eq "${#want[@]}" ] || continue
        for ((i = 0; i < ${#want[@]}; i++)); do [ "${CALL[$i]}" = "${want[$i]}" ] || continue 2; done
        return 0
    done < <(find "$SB/state/calls" -type f -name "*.$cmd" 2>/dev/null | sort)
    DETAIL="calls:${seen:- none}"
    return 1
}
argv_any() { local cmd=$1; shift; check "some $cmd call has argv: $*" argv_any_ "$cmd" "$@"; }
call_has_() { # call_has_ CMD N ARG -> argv of the Nth call contains ARG as one argument
    call_n "$1" "$2" || { DETAIL="no call #$2 of $1"; return 1; }
    local a
    DETAIL="got: ${CALL[*]}"
    for a in "${CALL[@]:1}"; do [ "$a" = "$3" ] && return 0; done
    return 1
}
call_pair_() { # call_pair_ CMD N A B -> A is directly followed by B
    call_n "$1" "$2" || { DETAIL="no call #$2 of $1"; return 1; }
    local i
    DETAIL="got: ${CALL[*]}"
    for ((i = 1; i + 1 < ${#CALL[@]}; i++)); do
        [ "${CALL[$i]}" = "$3" ] && [ "${CALL[$((i + 1))]}" = "$4" ] && return 0
    done
    return 1
}
has_arg()   { check "$1 call #$2 has arg: $3" call_has_ "$1" "$2" "$3"; }
lacks_arg() { check "$1 call #$2 lacks arg: $3" not call_has_ "$1" "$2" "$3"; }
has_pair()  { check "$1 call #$2 has: $3 $4" call_pair_ "$1" "$2" "$3" "$4"; }

# ------------------------------------------------------- presets and helpers
ETH=172.17.0.2        # what the fake `ip` reports for eth0

# a valid configuration of each tunnel type, as the host CLI would hand it over
cfg_oc()    { E TUNNEL_TYPE=vpn VPN_SERVER=vpn.example.com:10443 VPN_PROTOCOL=fortinet VPN_USER=username1 FAKE_UID=0; authf password hunter2; }
cfg_ipsec() { E TUNNEL_TYPE=vpn VPN_PROTOCOL=ipsec VPN_SERVER=203.0.113.10 VPN_USER=you@example.com FAKE_UID=0
              authf password xauth-pass; authf psk the-pre-shared-key; }
cfg_ssh()   { E TUNNEL_TYPE=ssh SSH_HOST=10.0.0.30 SSH_USER=username1; authf ssh_key FAKEKEY; }
cfg_local() { E TUNNEL_TYPE=local "FORWARDS=8080|10.0.0.5|80;"; }

SKIPS=0
skip() { SKIPS=$((SKIPS + 1)); printf 'SKIP - %s (%s)\n' "$CUR" "$1"; }

# run a tunnel until it is ready, then end it with status $1 (default 0)
up_and_down() { # up_and_down [STATUS]
    start_ep
    check "tunnel comes up (ready marker)" await_ready
    stop_tunnel "${1:-0}"
    finish_ep
}

# minimal readers for the example files (flat, two-level YAML; no yq needed)
yaml_get() { # yaml_get FILE KEY [SUBKEY] -> the scalar, comment and quotes stripped
    awk -v k="$2" -v s="${3:-}" '
        function clean(v) { sub(/[ \t]+#.*$/, "", v); sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
                            sub(/^"/, "", v); sub(/"$/, "", v); return v }
        s == "" && $0 ~ "^" k ":" { v = $0; sub("^" k ":", "", v); print clean(v); exit }
        s != "" && $0 ~ "^" k ":" { ink = 1; next }
        ink && /^[^ #]/ { ink = 0 }
        ink && $0 ~ "^  " s ":" { v = $0; sub("^  " s ":", "", v); print clean(v); exit }
    ' "$1"
}
yaml_list() { # yaml_list FILE KEY SUBKEY -> the "    - item" entries under KEY.SUBKEY, one per line
    awk -v k="$2" -v s="$3" '
        $0 ~ "^" k ":" { ink = 1; next }
        ink && /^[^ #]/ { ink = 0 }
        ink && $0 ~ "^  " s ":" { ins = 1; next }
        ins && /^[ \t]*#/ { next }
        ins && /^    - / { v = $0; sub(/^    - /, "", v); sub(/[ \t]+#.*$/, "", v); print v; next }
        ins { ins = 0 }
    ' "$1"
}
yaml_forwards() { # yaml_forwards FILE -> "IP REMOTE-PORT" per forward of the hosts: list
    awk '
        /^hosts:/ { inh = 1; next }
        inh && /^[^ #-]/ { inh = 0 }
        inh && /^  - ip:/ { ip = $0; sub(/^  - ip:[ \t]*/, "", ip); sub(/[ \t]+#.*$/, "", ip); next }
        inh && /\{[ \t]*remote:/ { r = $0; sub(/.*remote:[ \t]*/, "", r); sub(/[^0-9].*$/, "", r); print ip, r }
    ' "$1"
}
# the CLI picks the container-internal listen ports; any distinct ones do for the tests
example_forwards() { # example_forwards FILE -> "9000|ip|port;9001|ip|port;"
    local i=0 ip r out=""
    while read -r ip r; do out+="$((9000 + i))|$ip|$r;"; i=$((i + 1)); done < <(yaml_forwards "$1")
    printf '%s' "$out"
}

# ============================================================ preflight / env

begin "preflight: an unsupported TUNNEL_TYPE is refused"
E TUNNEL_TYPE=bogus; run_ep
rc 1; out_has "[t-forward] ERROR: unsupported TUNNEL_TYPE 'bogus'"; no_calls

begin "preflight: TUNNEL_TYPE empty means vpn, and vpn needs root"
run_ep
rc 1; out_has "ERROR: vpn mode needs root: run with --user 0 --cap-add NET_ADMIN --device /dev/net/tun"; no_calls

begin "preflight: TUNNEL_TYPE empty as root reaches the vpn field checks"
E FAKE_UID=0; run_ep
rc 1; out_has "ERROR: VPN_SERVER is required"; no_calls

begin "preflight: the auth directory is missing"
cfg_local; rmdir "$SB/auth"; run_ep
rc 1; out_has "ERROR: $SB/auth is missing or not writable by uid 10001 (mount the auth dir there)"; no_calls

begin "preflight: the auth directory is not writable"
cfg_local; chmod 500 "$SB/auth"
if [ -w "$SB/auth" ]; then
    skip "this user ignores directory permissions"
else
    run_ep
    rc 1; out_has "is missing or not writable by uid 10001"; no_calls
fi
chmod 700 "$SB/auth"

begin "preflight: no eth0 address"
cfg_local; E FAKE_NO_ETH0=1; run_ep
rc 1; out_has "ERROR: could not determine eth0 address"; no_calls

begin "preflight: markers left by a previous run of the container are removed before anything else"
cfg_local; E FORWARDS= SOCKS=false
touch "$SB/auth/ready" "$SB/auth/awaiting_code" "$SB/auth/code"
run_ep
rc 1; out_has "ERROR: local tunnel needs FORWARDS and/or SOCKS"
absent "$SB/auth/ready"; absent "$SB/auth/awaiting_code"; absent "$SB/auth/code"; no_calls

# ============================================================== required input

for miss in VPN_SERVER VPN_PROTOCOL VPN_USER; do
    begin "openconnect: $miss missing -> '$miss is required', exit 1, nothing started"
    cfg_oc; E "$miss="; run_ep
    rc 1; out_has "ERROR: $miss is required"; no_calls
done

begin "openconnect: /auth/password missing"
cfg_oc; rm "$SB/auth/password"; run_ep
rc 1; out_has "ERROR: /auth/password is missing"; no_calls

begin "openconnect: /auth/password empty"
cfg_oc; : >"$SB/auth/password"; run_ep
rc 1; out_has "ERROR: /auth/password is missing"; no_calls

begin "ipsec: VPN_SERVER missing"
cfg_ipsec; E VPN_SERVER=; run_ep
rc 1; out_has "ERROR: VPN_SERVER is required"; no_calls

begin "ipsec: VPN_USER missing"
cfg_ipsec; E VPN_USER=; run_ep
rc 1; out_has "ERROR: VPN_USER is required (XAuth user)"; no_calls

begin "ipsec: /auth/password missing"
cfg_ipsec; rm "$SB/auth/password"; run_ep
rc 1; out_has "ERROR: /auth/password is missing (XAuth password)"; no_calls

begin "ipsec: /auth/psk missing"
cfg_ipsec; rm "$SB/auth/psk"; run_ep
rc 1; out_has "ERROR: /auth/psk is missing (IKE pre-shared key)"; no_calls

for miss in SSH_HOST SSH_USER; do
    begin "ssh: $miss missing -> '$miss is required'"
    cfg_ssh; E "$miss="; run_ep
    rc 1; out_has "ERROR: $miss is required"; no_calls
done

begin "ssh: neither key nor password"
cfg_ssh; rm "$SB/auth/ssh_key"; run_ep
rc 1; out_has "ERROR: ssh needs /auth/ssh_key or /auth/password"; no_calls

begin "local: neither FORWARDS nor SOCKS"
E TUNNEL_TYPE=local; run_ep
rc 1; out_has "ERROR: local tunnel needs FORWARDS and/or SOCKS"; no_calls

begin "local: SOCKS=false and empty FORWARDS is still refused"
E TUNNEL_TYPE=local FORWARDS= SOCKS=false; run_ep
rc 1; out_has "ERROR: local tunnel needs FORWARDS and/or SOCKS"; no_calls

# ============================================== examples/*.yaml -> entrypoint

begin "example vpn.example.yaml: the SSL-VPN definition drives openconnect"
f=$EXAMPLES/vpn.example.yaml
server=$(yaml_get "$f" vpn server); proto=$(yaml_get "$f" vpn protocol); user=$(yaml_get "$f" vpn user)
pass=$(yaml_get "$f" vpn password); cert=$(yaml_get "$f" vpn servercert); group=$(yaml_get "$f" vpn authgroup)
nodtls=$(yaml_get "$f" vpn no_dtls); totp=$(yaml_get "$f" vpn totp)
check "the example defines server, protocol, user and password" test -n "$server$proto$user$pass" -a -n "$server" -a -n "$proto" -a -n "$user" -a -n "$pass"
check "the example is a vpn" test "$(yaml_get "$f" type)" = vpn
E TUNNEL_TYPE=vpn "VPN_SERVER=$server" "VPN_PROTOCOL=$proto" "VPN_USER=$user" "SERVERCERT=$cert" "AUTHGROUP=$group" \
  "TOTP=${totp:-false}" "NO_DTLS=${nodtls:-false}" FAKE_UID=0
authf password "$pass"
want=("--protocol=$proto" "$server" "--user=$user" --passwd-on-stdin --interface=tun0 --reconnect-timeout 300)
[ -z "$cert" ] || want+=(--servercert "$cert")
[ -z "$group" ] || want+=(--authgroup "$group")
[ "$nodtls" != true ] || want+=(--no-dtls)
stdin=$pass
[ "$totp" != true ] || { E FAKE_OC_LINES=2; stdin=$pass$'\n'123456; }
up_and_down 0
rc 0; argv openconnect 1 "${want[@]}"; file_is "$SB/state/openconnect.stdin" "$stdin"

begin "example vpn-imap.example.yaml: an emailed code is waited for and forwarded"
f=$EXAMPLES/vpn-imap.example.yaml
server=$(yaml_get "$f" vpn server); proto=$(yaml_get "$f" vpn protocol); user=$(yaml_get "$f" vpn user)
pass=$(yaml_get "$f" vpn password); totp=$(yaml_get "$f" vpn totp)
check "the example defines server, protocol, user, password and totp: true" test -n "$server" -a -n "$proto" -a -n "$user" -a -n "$pass" -a "$totp" = true
E TUNNEL_TYPE=vpn "VPN_SERVER=$server" "VPN_PROTOCOL=$proto" "VPN_USER=$user" TOTP=true FAKE_UID=0 FAKE_OC_LINES=2
authf password "$pass"
up_and_down 0
rc 0
argv openconnect 1 "--protocol=$proto" "$server" "--user=$user" --passwd-on-stdin --interface=tun0 --reconnect-timeout 300
file_is "$SB/state/openconnect.stdin" "$pass"$'\n'123456
out_has "password sent; waiting for verification code from the host"; out_has "verification code forwarded"
absent "$SB/auth/code"; absent "$SB/auth/awaiting_code"

begin "example ipsec.example.yaml: the IPsec definition drives strongSwan"
f=$EXAMPLES/ipsec.example.yaml
server=$(yaml_get "$f" vpn server); ikev=$(yaml_get "$f" vpn ikev); psk=$(yaml_get "$f" vpn psk)
user=$(yaml_get "$f" vpn user); pass=$(yaml_get "$f" vpn password); ikep=$(yaml_get "$f" vpn ike_proposal)
espp=$(yaml_get "$f" vpn esp_proposal); totp=$(yaml_get "$f" vpn totp)
check "the example selects protocol ipsec" test "$(yaml_get "$f" vpn protocol)" = ipsec
check "the example defines server, ikev, psk, user and password" test -n "$server" -a -n "$ikev" -a -n "$psk" -a -n "$user" -a -n "$pass"
E TUNNEL_TYPE=vpn VPN_PROTOCOL=ipsec "VPN_SERVER=$server" "VPN_USER=$user" "IKE_VERSION=$ikev" "IKE_PROPOSAL=$ikep" \
  "ESP_PROPOSAL=$espp" "TOTP=${totp:-false}" FAKE_UID=0
authf password "$pass"; authf psk "$psk"
up_and_down 0
rc 0; argv ipsec 1 start --nofork
conf=$SB/etc/ipsec.conf; sec=$SB/etc/ipsec.secrets
file_has "$conf" "    keyexchange=ikev$ikev"; file_has "$conf" "    right=$server"; file_has "$conf" "    xauth_identity=$user"
file_has "$conf" "    ike=${ikep:-aes256-sha256-modp2048,aes128-sha256-modp2048}!"
file_has "$conf" "    esp=${espp:-aes256-sha256-modp1536,aes128-sha256-modp1536}!"
file_has "$sec" ": PSK \"$psk\""; file_has "$sec" "$user : XAUTH \"$pass\""
out_has "connecting to $server (protocol: ipsec/ikev$ikev, user: $user)"

begin "example ssh-jump.example.yaml: key auth through a jump chain with forwards and SOCKS"
f=$EXAMPLES/ssh-jump.example.yaml
host=$(yaml_get "$f" ssh host); user=$(yaml_get "$f" ssh user); port=$(yaml_get "$f" ssh port)
jump=$(yaml_list "$f" ssh jump | tr '\n' ' '); jump=${jump% }
socks=$(yaml_get "$f" socks); fwd=$(example_forwards "$f")
check "the example is an ssh tunnel with host, user, jump hops and forwards" test "$(yaml_get "$f" type)" = ssh -a -n "$host" -a -n "$user" -a -n "$jump" -a -n "$fwd"
E TUNNEL_TYPE=ssh "SSH_HOST=$host" "SSH_USER=$user" "SSH_PORT=$port" "SSH_JUMP=$jump" "FORWARDS=$fwd" "SOCKS=${socks:+true}"
authf ssh_key FAKEKEY
hops=()
for h in $jump; do
    hu=$user; hh=$h; hp=22
    case "$hh" in *@*) hu=${hh%%@*}; hh=${hh#*@} ;; esac
    case "$hh" in *:*) hp=${hh##*:}; hh=${hh%:*} ;; esac
    hops+=("$hu@$hh:$hp")
done
want=(-o BatchMode=yes -N -p "$port" -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3
      -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$SB/auth/known_hosts"
      -i "$SB/home/.tforward/ssh_key" -o IdentitiesOnly=yes -J "$(IFS=,; echo "${hops[*]}")")
IFS=';' read -ra specs <<<"$fwd"
for s in "${specs[@]}"; do IFS='|' read -r lp rh rp <<<"$s"; want+=(-L "$ETH:$lp:$rh:$rp"); done
[ -z "$socks" ] || want+=(-D "$ETH:1080")
want+=("$user@$host")
up_and_down 0
rc 0; argv ssh 1 "${want[@]}"; calls_are sshpass 0

begin "example local.example.yaml: one socat per forward"
f=$EXAMPLES/local.example.yaml
fwd=$(example_forwards "$f")
check "the example is a local tunnel with forwards" test "$(yaml_get "$f" type)" = local -a -n "$fwd"
E TUNNEL_TYPE=local "FORWARDS=$fwd"
start_ep
check "tunnel comes up (ready marker)" await_ready
i=0
IFS=';' read -ra specs <<<"$fwd"
for s in "${specs[@]}"; do
    IFS='|' read -r lp rh rp <<<"$s"
    i=$((i + 1))
    argv_any socat -d -d "TCP-LISTEN:$lp,bind=$ETH,fork,reuseaddr" "TCP:$rh:$rp"
done
calls_are socat "$i"; calls_are microsocks 0
kill -TERM "$EP_PID"; finish_ep

begin "examples: every example with a tunnel type is covered by this suite"
n=0
for f in "$EXAMPLES"/*.yaml; do
    t=$(yaml_get "$f" type)
    [ -n "$t" ] || continue          # scan.example.yaml is not a tunnel
    n=$((n + 1))
    case "$(basename "$f")" in
        vpn.example.yaml|vpn-imap.example.yaml|ipsec.example.yaml|ssh-jump.example.yaml|local.example.yaml) ;;
        *) check "$(basename "$f") (type $t) has a scenario above" false ;;
    esac
done
check "the examples directory still has tunnel definitions (found $n)" test "$n" -ge 5

# ================================================================= openconnect

begin "openconnect: baseline - argv, password over the FIFO, markers, exit status"
cfg_oc; E FORWARDS= SOCKS=false
up_and_down 7
rc 7; ended
argv openconnect 1 --protocol=fortinet vpn.example.com:10443 --user=username1 --passwd-on-stdin --interface=tun0 --reconnect-timeout 300
file_is "$SB/state/openconnect.stdin" hunter2
absent "$SB/auth/password"; exists "$SB/auth/ready"
calls_are openconnect 1; calls_are socat 0; calls_are microsocks 0
out_has "[t-forward] connecting to vpn.example.com:10443 (protocol: fortinet, user: username1)"
out_has "[t-forward] waiting for tunnel interface (max 5s)"; out_has "[t-forward] tunnel is up: tun0 10.8.0.2"
out_has "[t-forward] READY"; out_has "[t-forward] openconnect exited with status 7"

begin "openconnect: status 0 of the tunnel process is the container's status 0"
cfg_oc; up_and_down 0
rc 0; out_has "openconnect exited with status 0"

begin "openconnect: every optional setting reaches the command line, in order"
cfg_oc; E VPN_PROTOCOL=gp SERVERCERT=pin-sha256:AAAA= AUTHGROUP=Staff NO_DTLS=true
authf totp_secret base32:JBSWY3DPEHPK3PXP
up_and_down 0
rc 0
argv openconnect 1 --protocol=gp vpn.example.com:10443 --user=username1 --passwd-on-stdin --interface=tun0 --reconnect-timeout 300 \
    --servercert pin-sha256:AAAA= --authgroup Staff --no-dtls --token-mode=totp "--token-secret=@$SB/auth/totp_secret"
absent "$SB/auth/awaiting_code"; out_lacks "waiting for verification code"

begin "openconnect: NO_DTLS=false, empty AUTHGROUP and empty SERVERCERT add nothing"
cfg_oc; E NO_DTLS=false AUTHGROUP= SERVERCERT=
up_and_down 0
argv openconnect 1 --protocol=fortinet vpn.example.com:10443 --user=username1 --passwd-on-stdin --interface=tun0 --reconnect-timeout 300

begin "openconnect: forwards and SOCKS start after the tunnel is up and before READY"
cfg_oc; E "FORWARDS=2222|10.0.0.20|22;;8080|10.0.0.20|80;" SOCKS=true
up_and_down 0
rc 0
argv_any socat -d -d "TCP-LISTEN:2222,bind=$ETH,fork,reuseaddr" TCP:10.0.0.20:22
argv_any socat -d -d "TCP-LISTEN:8080,bind=$ETH,fork,reuseaddr" TCP:10.0.0.20:80
calls_are socat 2
argv microsocks 1 -i "$ETH" -p 1080
out_has "forward: $ETH:2222 -> 10.0.0.20:22"; out_has "SOCKS5 proxy on $ETH:1080"

begin "openconnect: a TOTP secret file means no round-trip with the host"
cfg_oc; E TOTP=true; authf totp_secret base32:JBSWY3DPEHPK3PXP
up_and_down 0
rc 0; out_lacks "waiting for verification code"; has_arg openconnect 1 --token-mode=totp

begin "openconnect: KEEP_AUTH=false erases the credentials once connected"
cfg_oc; authf totp_secret base32:JBSWY3DPEHPK3PXP; authf ssh_key stray
start_ep
check "tunnel comes up (ready marker)" await_ready
absent "$SB/auth/password"; absent "$SB/auth/totp_secret"; absent "$SB/auth/ssh_key"
stop_tunnel 0; finish_ep

begin "openconnect: KEEP_AUTH=true keeps the credentials for the restart policy"
cfg_oc; E KEEP_AUTH=true; authf totp_secret base32:JBSWY3DPEHPK3PXP
start_ep
check "tunnel comes up (ready marker)" await_ready
exists "$SB/auth/password"; exists "$SB/auth/totp_secret"
stop_tunnel 0; finish_ep
file_is "$SB/state/openconnect.stdin" hunter2

begin "openconnect: manual TOTP - waits for /auth/code, forwards it, cleans up"
cfg_oc; E TOTP=true FAKE_OC_LINES=2
up_and_down 0
rc 0
file_is "$SB/state/openconnect.stdin" hunter2$'\n'123456
out_has "password sent; waiting for verification code from the host"; out_has "verification code forwarded"
absent "$SB/auth/code"; absent "$SB/auth/awaiting_code"; absent "$SB/auth/password"

begin "openconnect: manual TOTP - no code in time -> error naming the limit, exit 1"
cfg_oc; E TOTP=true FAKE_OC_LINES=2 CODE_TIMEOUT=2
run_ep
rc 1; out_has "ERROR: no verification code within 2s; aborting"; exists "$SB/auth/awaiting_code"; absent "$SB/auth/ready"

begin "openconnect: tunnel never comes up -> bounded by CONNECT_TIMEOUT, exit 1"
cfg_oc; E FAKE_OC_MODE=notun CONNECT_TIMEOUT=3
run_ep
rc 1; out_has "ERROR: tunnel did not come up within 3s"; absent "$SB/auth/ready"

begin "openconnect: openconnect exits before the tunnel is up"
cfg_oc; E FAKE_OC_MODE=exit FAKE_OC_RC=3
run_ep
rc 1; out_has "ERROR: openconnect exited (authentication failed?)"; absent "$SB/auth/ready"

begin "openconnect: openconnect exits while waiting for the verification code"
cfg_oc; E FAKE_OC_MODE=exit TOTP=true
run_ep
rc 1; out_has "ERROR: openconnect exited during authentication"

begin "openconnect: rejected credentials are reported instead of waiting"
cfg_oc; E FAKE_OC_MODE=reject
run_ep
rc 1; out_has "ERROR: the VPN rejected the credentials (wrong password?) — check vpn.password in the config"

begin "openconnect: rejected credentials while waiting for the verification code"
cfg_oc; E FAKE_OC_MODE=reject TOTP=true FAKE_OC_LINES=2
run_ep
rc 1; out_has "ERROR: the VPN rejected the credentials (wrong password?)"

begin "openconnect: untrusted certificate without a pin -> advice to pin or opt in to tofu"
cfg_oc; E FAKE_OC_MODE=certbad
run_ep
rc 1; out_has "ERROR: the server certificate is not trusted by a public CA."; out_has "vpn.tofu: true"

begin "openconnect: certificate differs from the pin -> pinned and presented pin are named"
cfg_oc; E FAKE_OC_MODE=certpin SERVERCERT=pin-sha256:PINNED=
run_ep
rc 1
out_has "ERROR: the server certificate does not match the pinned vpn.servercert (pinned pin-sha256:PINNED=, server presented pin-sha256:PRESENTEDPIN+/=)"

# --- trust on first use
begin "tofu: first start probes, stores the pin (mode 600) and enforces it"
cfg_oc; E SERVERCERT_TOFU=true FAKE_OC_PIN=pin-sha256:LEARNED=
up_and_down 0
rc 0; calls_are openconnect 2
argv openconnect 1 --protocol=fortinet vpn.example.com:10443 --user=username1 --non-inter
argv openconnect 2 --protocol=fortinet vpn.example.com:10443 --user=username1 --passwd-on-stdin --interface=tun0 --reconnect-timeout 300 \
    --servercert pin-sha256:LEARNED=
file_is "$SB/auth/learned_servercert" pin-sha256:LEARNED=; mode_is "$SB/auth/learned_servercert" 600
out_has "tofu: no servercert pinned yet; learning the server certificate pin"; out_has "SECURITY: trust-on-first-use - trusting pin-sha256:LEARNED="

begin "tofu: a pin learned earlier is enforced on restart without probing again"
cfg_oc; E SERVERCERT_TOFU=true FAKE_OC_PIN=pin-sha256:ATTACKER=
authf learned_servercert pin-sha256:LEARNED=
up_and_down 0
rc 0; calls_are openconnect 1; has_pair openconnect 1 --servercert pin-sha256:LEARNED=
out_has "tofu: enforcing the pin learned earlier (pin-sha256:LEARNED=)"; out_lacks "learning the server certificate pin"

begin "tofu: a learned_servercert with garbage in it is ignored (probe runs)"
cfg_oc; E SERVERCERT_TOFU=true FAKE_OC_PIN=pin-sha256:FRESH=
authf learned_servercert 'not a pin; rm -rf /'
up_and_down 0
rc 0; calls_are openconnect 2; has_pair openconnect 2 --servercert pin-sha256:FRESH=

begin "tofu: a symlinked learned_servercert is not followed"
cfg_oc; E SERVERCERT_TOFU=true FAKE_OC_PIN=pin-sha256:FRESH=
printf 'pin-sha256:SYMLINKED=\n' >"$SB/elsewhere"; ln -s "$SB/elsewhere" "$SB/auth/learned_servercert"
up_and_down 0
rc 0; calls_are openconnect 2; has_pair openconnect 2 --servercert pin-sha256:FRESH=

begin "tofu: an explicit SERVERCERT wins, no probe"
cfg_oc; E SERVERCERT_TOFU=true SERVERCERT=pin-sha256:CONFIGURED= FAKE_OC_PIN=pin-sha256:ATTACKER=
authf learned_servercert pin-sha256:LEARNED=
up_and_down 0
rc 0; calls_are openconnect 1; has_pair openconnect 1 --servercert pin-sha256:CONFIGURED=

begin "tofu: off - a learned_servercert file is not used"
cfg_oc; authf learned_servercert pin-sha256:LEARNED=
up_and_down 0
rc 0; calls_are openconnect 1; lacks_arg openconnect 1 --servercert

begin "tofu: the probe prints no pin (CA-trusted) -> connects without one, stores nothing"
cfg_oc; E SERVERCERT_TOFU=true
up_and_down 0
rc 0; calls_are openconnect 2; lacks_arg openconnect 2 --servercert
absent "$SB/auth/learned_servercert"; out_has "tofu: no pin printed"

# ===================================================================== ipsec

begin "ipsec: baseline - starter, ipsec.conf, ipsec.secrets (600), markers"
cfg_ipsec; E FORWARDS= SOCKS=false
up_and_down 5
rc 5; ended
argv ipsec 1 start --nofork
conf=$SB/etc/ipsec.conf; sec=$SB/etc/ipsec.secrets
file_has "$conf" "conn tforward"; file_has "$conf" "    keyexchange=ikev1"; file_has "$conf" "    aggressive=yes"
file_has "$conf" "    authby=xauthpsk"; file_has "$conf" "    xauth=client"; file_has "$conf" "    right=203.0.113.10"
file_has "$conf" "    xauth_identity=you@example.com"
file_has "$conf" "    ike=aes256-sha256-modp2048,aes128-sha256-modp2048!"
file_has "$conf" "    esp=aes256-sha256-modp1536,aes128-sha256-modp1536!"
file_has "$conf" "    ikelifetime=28800s"; file_has "$conf" "    lifetime=43200s"; file_has "$conf" "    auto=start"
file_lacks "$conf" "leftid="; file_lacks "$conf" "rightid="
file_is "$sec" ': PSK "the-pre-shared-key"'$'\n''you@example.com : XAUTH "xauth-pass"'
mode_is "$sec" 600
absent "$SB/auth/psk"; absent "$SB/auth/password"; exists "$SB/auth/ready"
out_has "[t-forward] connecting to 203.0.113.10 (protocol: ipsec/ikev1, user: you@example.com)"
out_has "waiting for IPsec SA (max 5s)"; out_has "[t-forward] IPsec tunnel is up"; out_lacks "virtual IP"
out_has "[t-forward] READY"; out_has "[t-forward] charon exited with status 5"
calls_are openconnect 0

begin "ipsec: IKEv2, custom proposals, lifetimes and ids reach ipsec.conf; a virtual IP is reported"
cfg_ipsec; E IKE_VERSION=2 IKE_PROPOSAL=aes128-sha1-modp1024 ESP_PROPOSAL=aes128-sha1 IPSEC_IKELIFETIME=3600s \
  IPSEC_LIFETIME=2h IPSEC_LOCALID=dialup-group IPSEC_REMOTEID=@gw.example.com FAKE_IPSEC_VIP=1
up_and_down 0
rc 0
file_has "$SB/etc/ipsec.conf" "    keyexchange=ikev2"; file_has "$SB/etc/ipsec.conf" "    aggressive=no"
file_has "$SB/etc/ipsec.conf" "    ike=aes128-sha1-modp1024!"; file_has "$SB/etc/ipsec.conf" "    esp=aes128-sha1!"
file_has "$SB/etc/ipsec.conf" "    ikelifetime=3600s"; file_has "$SB/etc/ipsec.conf" "    lifetime=2h"
file_has "$SB/etc/ipsec.conf" "    leftid=dialup-group"; file_has "$SB/etc/ipsec.conf" "    rightid=@gw.example.com"
out_has "protocol: ipsec/ikev2"; out_has "IPsec tunnel is up (virtual IP 10.99.0.5)"

begin "ipsec: forwards and SOCKS run on the published side after the SA is up"
cfg_ipsec; E "FORWARDS=2222|10.0.0.20|22;" SOCKS=true
up_and_down 0
rc 0; argv_any socat -d -d "TCP-LISTEN:2222,bind=$ETH,fork,reuseaddr" TCP:10.0.0.20:22; argv microsocks 1 -i "$ETH" -p 1080

begin "ipsec: KEEP_AUTH=true keeps psk and password in /auth (secrets still written)"
cfg_ipsec; E KEEP_AUTH=true
up_and_down 0
exists "$SB/auth/psk"; exists "$SB/auth/password"; exists "$SB/etc/ipsec.secrets"

begin "ipsec: a PSK with a double quote is written single-quoted"
cfg_ipsec; authf psk 'pa"ss'
up_and_down 0
file_has "$SB/etc/ipsec.secrets" ": PSK 'pa\"ss'"

begin "ipsec: manual TOTP - the code is appended to the XAuth password"
cfg_ipsec; E TOTP=true
up_and_down 0
rc 0; file_has "$SB/etc/ipsec.secrets" 'you@example.com : XAUTH "xauth-pass123456"'
out_has "XAuth password set; waiting for verification code from the host"; out_has "verification code appended to XAuth password"
absent "$SB/auth/code"; absent "$SB/auth/awaiting_code"

begin "ipsec: manual TOTP - no code in time -> error naming the limit, exit 1"
cfg_ipsec; E TOTP=true CODE_TIMEOUT=2
run_ep
rc 1; out_has "ERROR: no verification code within 2s; aborting"; calls_are ipsec 0; absent "$SB/etc/ipsec.conf"

begin "ipsec: a totp_secret generates the code locally (base32: prefix stripped)"
cfg_ipsec; authf totp_secret base32:JBSWY3DPEHPK3PXP
up_and_down 0
rc 0; argv oathtool 1 --totp -b JBSWY3DPEHPK3PXP
file_has "$SB/etc/ipsec.secrets" 'you@example.com : XAUTH "xauth-pass654321"'
out_has "generated TOTP appended to XAuth password"

# every value interpolated into ipsec.conf / ipsec.secrets is validated first:
# a line break there would add a directive of its own (leftupdown= runs a command)
inject_case() { # inject_case DESCRIPTION EXPECTED-NAME VAR=VALUE
    begin "ipsec: $1 is refused before any file is written"
    cfg_ipsec; E "$3"; run_ep
    rc 1; out_has "ERROR: invalid $2 for ipsec (control characters, quotes or an unexpected format are not allowed)"
    absent "$SB/etc/ipsec.conf"; absent "$SB/etc/ipsec.secrets"; calls_are ipsec 0
}
inject_case "a line break in IPSEC_LOCALID"    IPSEC_LOCALID  $'IPSEC_LOCALID=grp\nleftupdown=/tmp/evil'
inject_case "a line break in IPSEC_REMOTEID"   IPSEC_REMOTEID $'IPSEC_REMOTEID=gw\nleftupdown=/tmp/evil'
inject_case "whitespace in VPN_SERVER"         VPN_SERVER     'VPN_SERVER=gw.example.com leftupdown=/tmp/evil'
inject_case "a double quote in VPN_USER"       VPN_USER       'VPN_USER=me"; leftupdown=/tmp/evil'
inject_case "IKE_VERSION=3"                    IKE_VERSION    IKE_VERSION=3
inject_case "a shell metacharacter in IKE_PROPOSAL"  IKE_PROPOSAL 'IKE_PROPOSAL=aes256;touch /tmp/evil'
inject_case "a space in ESP_PROPOSAL"          ESP_PROPOSAL   'ESP_PROPOSAL=aes256 sha256'
inject_case "a non-time IPSEC_IKELIFETIME"     IPSEC_IKELIFETIME IPSEC_IKELIFETIME=forever
inject_case "a trailing command in IPSEC_LIFETIME" IPSEC_LIFETIME 'IPSEC_LIFETIME=1h; reboot'

begin "ipsec: a line break in the PSK is refused"
cfg_ipsec; authf psk $'line1\nline2'; run_ep
rc 1; out_has "ERROR: PSK contains a line break or control character"; absent "$SB/etc/ipsec.secrets"; calls_are ipsec 0

begin "ipsec: a PSK with both quote kinds is refused"
cfg_ipsec; authf psk "it's \"both\""; run_ep
rc 1; out_has "ERROR: PSK contains both ' and \" which ipsec.secrets cannot represent"; absent "$SB/etc/ipsec.secrets"

begin "ipsec: a line break in the XAuth password is refused"
cfg_ipsec; authf password $'pw\nsecond'; run_ep
rc 1; out_has "ERROR: XAuth password contains a line break or control character"; calls_are ipsec 0

begin "ipsec: rejected XAuth/PSK is reported instead of waiting"
cfg_ipsec; E FAKE_IPSEC_MODE=xauth
run_ep
rc 1; out_has "ERROR: the VPN rejected the credentials (XAuth/PSK) — check vpn.psk / vpn.user / vpn.password"; absent "$SB/auth/ready"

begin "ipsec: NO_PROPOSAL_CHOSEN points at the proposal settings"
cfg_ipsec; E FAKE_IPSEC_MODE=proposal
run_ep
rc 1; out_has "ERROR: no matching proposal — set vpn.ike_proposal / vpn.esp_proposal to the gateway's Phase1/Phase2 algorithms"

begin "ipsec: charon dying during negotiation"
cfg_ipsec; E FAKE_IPSEC_MODE=exit
run_ep
rc 1; out_has "ERROR: charon exited during negotiation"; absent "$SB/auth/ready"

begin "ipsec: negotiation that never finishes is bounded by CONNECT_TIMEOUT"
cfg_ipsec; E FAKE_IPSEC_MODE=hang CONNECT_TIMEOUT=3
run_ep
rc 1; out_has "ERROR: IPsec tunnel did not come up within 3s"; absent "$SB/auth/ready"

# ======================================================================== ssh

begin "ssh: key auth - exact command line, private 0600 key copy, markers"
cfg_ssh; E "FORWARDS=2222|10.0.0.40|22;5433|10.0.0.40|5432;" SOCKS=true
up_and_down 255
rc 255; ended
argv ssh 1 -o BatchMode=yes -N -p 22 -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$SB/auth/known_hosts" \
    -i "$SB/home/.tforward/ssh_key" -o IdentitiesOnly=yes \
    -L "$ETH:2222:10.0.0.40:22" -L "$ETH:5433:10.0.0.40:5432" -D "$ETH:1080" username1@10.0.0.30
calls_are ssh 1; calls_are sshpass 0
file_is "$SB/state/ssh.keycontent" FAKEKEY; state_has ssh.keymode 600
mode_is "$SB/home/.tforward" 700
absent "$SB/home/.tforward/ssh_key"; absent "$SB/auth/ssh_key"; exists "$SB/auth/ready"
out_has "forward: $ETH:2222 -> 10.0.0.40:22 (via ssh)"; out_has "forward: $ETH:5433 -> 10.0.0.40:5432 (via ssh)"
out_has "SOCKS5 (ssh -D) on $ETH:1080"; out_has "connecting to username1@10.0.0.30:22"
out_has "[t-forward] READY"; out_has "[t-forward] ssh exited with status 255"

begin "ssh: password auth goes through sshpass -f, with no BatchMode and no -i"
cfg_ssh; rm "$SB/auth/ssh_key"; authf password s3cret; E "FORWARDS=2222|10.0.0.40|22;" SSH_PORT=2200
up_and_down 0
rc 0
argv sshpass 1 -f "$SB/auth/password" ssh -N -p 2200 -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$SB/auth/known_hosts" \
    -L "$ETH:2222:10.0.0.40:22" username1@10.0.0.30
file_is "$SB/state/sshpass.password" s3cret
absent "$SB/auth/password"; out_has "connecting to username1@10.0.0.30:2200"

begin "ssh: with a key and a password, the key is used"
cfg_ssh; authf password s3cret; E "FORWARDS=2222|10.0.0.40|22;"
up_and_down 0
calls_are sshpass 0; has_pair ssh 1 -o BatchMode=yes

begin "ssh: no forwards and no SOCKS -> ready at once, no listener probe"
cfg_ssh
up_and_down 0
rc 0; argv ssh 1 -o BatchMode=yes -N -p 22 -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$SB/auth/known_hosts" \
    -i "$SB/home/.tforward/ssh_key" -o IdentitiesOnly=yes username1@10.0.0.30

begin "ssh: SOCKS only"
cfg_ssh; E SOCKS=true
up_and_down 0
has_pair ssh 1 -D "$ETH:1080"; lacks_arg ssh 1 -L

begin "ssh: KEEP_AUTH=true keeps the key for the restart policy"
cfg_ssh; E KEEP_AUTH=true "FORWARDS=2222|10.0.0.40|22;"
start_ep
check "tunnel comes up (ready marker)" await_ready
exists "$SB/auth/ssh_key"; exists "$SB/home/.tforward/ssh_key"
stop_tunnel 0; finish_ep

begin "ssh: strict host key checking needs a stored host key"
cfg_ssh; E SSH_STRICT_HOST_KEY=true "FORWARDS=2222|10.0.0.40|22;"; run_ep
rc 1; out_has "ERROR: ssh.strict_host_key is on but no known host key is stored for this tunnel"; calls_are ssh 0

begin "ssh: strict host key checking with a stored host key"
cfg_ssh; E SSH_STRICT_HOST_KEY=true "FORWARDS=2222|10.0.0.40|22;"; authf known_hosts '10.0.0.30 ssh-ed25519 AAAAFAKE'
up_and_down 0
rc 0; has_pair ssh 1 -o StrictHostKeyChecking=yes; file_is "$SB/auth/known_hosts" '10.0.0.30 ssh-ed25519 AAAAFAKE'

begin "ssh: jump hosts become one -J chain (user and port default to the tunnel's / 22)"
cfg_ssh; E "SSH_JUMP=10.0.0.10 admin@10.0.0.20:2222 bastion:2200"
up_and_down 0
rc 0; has_pair ssh 1 -J "username1@10.0.0.10:22,admin@10.0.0.20:2222,username1@bastion:2200"
out_has "jump chain: username1@10.0.0.10:22 admin@10.0.0.20:2222 username1@bastion:2200 -> 10.0.0.30"

begin "ssh: comma-separated jump hosts work too"
cfg_ssh; E "SSH_JUMP=a.example,b.example"
up_and_down 0
has_pair ssh 1 -J "username1@a.example:22,username1@b.example:22"

begin "ssh: a jump entry is never globbed against the working directory"
cfg_ssh; touch "$SB/work/alpha" "$SB/work/beta"; E 'SSH_JUMP=*'
up_and_down 0
has_pair ssh 1 -J 'username1@*:22'

begin "ssh: jump hosts need key auth"
cfg_ssh; rm "$SB/auth/ssh_key"; authf password s3cret; E SSH_JUMP=10.0.0.10; run_ep
rc 1; out_has "ERROR: SSH_JUMP (multi-hop) needs key auth (/auth/ssh_key), not a password"; calls_are ssh 0; calls_are sshpass 0

begin "ssh: authentication failure"
cfg_ssh; E "FORWARDS=2222|10.0.0.40|22;" FAKE_SSH_MODE=denied; run_ep
rc 1; out_has "ERROR: ssh exited (authentication failed?)"; absent "$SB/auth/ready"

begin "ssh: a changed or untrusted host key is called out"
cfg_ssh; E "FORWARDS=2222|10.0.0.40|22;" FAKE_SSH_MODE=hostkey; run_ep
rc 1; out_has "ERROR: the ssh host key for 10.0.0.30 changed or is not trusted"; absent "$SB/auth/ready"

begin "ssh: listeners that never appear are bounded by CONNECT_TIMEOUT"
cfg_ssh; E "FORWARDS=2222|10.0.0.40|22;" FAKE_SSH_MODE=slow CONNECT_TIMEOUT=3; run_ep
rc 1; out_has "ERROR: ssh did not come up within 3s"; absent "$SB/auth/ready"

# ===================================================================== local

begin "local: one socat per forward on the published address, SOCKS off"
cfg_local; E "FORWARDS=8080|10.0.0.5|80;;9100|192.168.1.77|9100;"
start_ep
check "tunnel comes up (ready marker)" await_ready
argv_any socat -d -d "TCP-LISTEN:8080,bind=$ETH,fork,reuseaddr" TCP:10.0.0.5:80
argv_any socat -d -d "TCP-LISTEN:9100,bind=$ETH,fork,reuseaddr" TCP:192.168.1.77:9100
calls_are socat 2; calls_are microsocks 0
check "the entrypoint keeps running" ep_alive
kill -TERM "$EP_PID"; finish_ep
out_has "forward: $ETH:8080 -> 10.0.0.5:80"; out_has "forward: $ETH:9100 -> 192.168.1.77:9100"; out_has "[t-forward] READY"

begin "local: SOCKS only"
E TUNNEL_TYPE=local SOCKS=true
start_ep
check "tunnel comes up (ready marker)" await_ready
argv microsocks 1 -i "$ETH" -p 1080; calls_are socat 0
kill -TERM "$EP_PID"; finish_ep
out_has "SOCKS5 proxy on $ETH:1080"

begin "local: the published address comes from eth0"
cfg_local; E FAKE_ETH_IP=10.1.2.3 SOCKS=true
start_ep
check "tunnel comes up (ready marker)" await_ready
has_arg socat 1 "TCP-LISTEN:8080,bind=10.1.2.3,fork,reuseaddr"; argv microsocks 1 -i 10.1.2.3 -p 1080
kill -TERM "$EP_PID"; finish_ep

# ============================================================ shutdown (TERM)
# `docker stop` sends TERM. entrypoint.sh installs no trap, so a TERM ends the
# shell with the conventional 128+15 status while it waits on the tunnel process;
# the tunnel itself is not signalled by the script (the container going away
# takes it down). PID 1 ignoring default-action signals is a property of the
# container runtime (docker run --init / tini), which is not testable here.

begin "shutdown: TERM during openconnect ends the entrypoint with status 143, READY already reported"
cfg_oc; E "FORWARDS=8080|10.0.0.5|80;"
start_ep
check "tunnel comes up (ready marker)" await_ready
kill -TERM "$EP_PID"; finish_ep
rc 143; ended; out_lacks "openconnect exited with status"

begin "shutdown: TERM during ipsec ends the entrypoint with status 143"
cfg_ipsec
start_ep
check "tunnel comes up (ready marker)" await_ready
kill -TERM "$EP_PID"; finish_ep
rc 143; ended; out_lacks "charon exited with status"

begin "shutdown: TERM during ssh ends the entrypoint with status 143"
cfg_ssh; E "FORWARDS=2222|10.0.0.40|22;"
start_ep
check "tunnel comes up (ready marker)" await_ready
kill -TERM "$EP_PID"; finish_ep
rc 143; ended; out_lacks "ssh exited with status"

begin "shutdown: TERM during local ends the entrypoint with status 143"
cfg_local
start_ep
check "tunnel comes up (ready marker)" await_ready
kill -TERM "$EP_PID"; finish_ep
rc 143; ended

begin "shutdown: TERM while openconnect is still connecting (no tunnel yet) also ends it"
cfg_oc; E FAKE_OC_MODE=notun CONNECT_TIMEOUT=30
start_ep
await_file "$SB/state/openconnect.stdin" || true
kill -TERM "$EP_PID"; finish_ep
rc 143; ended; absent "$SB/auth/ready"

# ======================================================== restart / bounded loops
# The host CLI runs a --restart tunnel with Docker's `unless-stopped` policy and
# KEEP_AUTH=true: the same container is started again over the same auth dir.

begin "restart: KEEP_AUTH=true - the second start re-authenticates from the kept password and clears the stale marker"
cfg_oc; E KEEP_AUTH=true
up_and_down 1
rc 1; exists "$SB/auth/ready"; exists "$SB/auth/password"
reset_state
E FAKE_OC_MODE=notun CONNECT_TIMEOUT=2
run_ep
rc 1; out_has "ERROR: tunnel did not come up within 2s"
absent "$SB/auth/ready"; file_is "$SB/state/openconnect.stdin" hunter2

begin "restart: without KEEP_AUTH the credentials are gone, so the next start fails fast"
cfg_oc
up_and_down 1
rc 1; absent "$SB/auth/password"; exists "$SB/auth/ready"
reset_state
run_ep
rc 1; out_has "ERROR: /auth/password is missing"; absent "$SB/auth/ready"; no_calls

begin "restart: ipsec KEEP_AUTH=true starts again from the kept psk and password"
cfg_ipsec; E KEEP_AUTH=true
up_and_down 1
rc 1; exists "$SB/auth/psk"
reset_state
up_and_down 0
rc 0; file_has "$SB/etc/ipsec.secrets" ': PSK "the-pre-shared-key"'

begin "restart: ssh KEEP_AUTH=true starts again from the kept key"
cfg_ssh; E KEEP_AUTH=true "FORWARDS=2222|10.0.0.40|22;"
up_and_down 255
rc 255
reset_state
up_and_down 0
rc 0; file_is "$SB/state/ssh.keycontent" FAKEKEY

begin "restart: a start whose tunnel keeps failing exits every time (no internal retry loop)"
cfg_ssh; E "FORWARDS=2222|10.0.0.40|22;" FAKE_SSH_MODE=denied KEEP_AUTH=true
run_ep; rc 1; calls_are ssh 1
reset_state; run_ep; rc 1; calls_are ssh 1

# =================================================================== summary
flush_failure
printf '\n%d tests, %d assertions, %d failed, %d skipped\n' "$TESTS" "$ASSERTIONS" "$FAILS" "$SKIPS"
[ "$FAILS" -eq 0 ]
