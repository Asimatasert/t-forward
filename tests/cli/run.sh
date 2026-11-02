#!/usr/bin/env bash
#
# Black-box tests for the t-forward bash CLI, run against a FAKE docker.
#
#   bash tests/cli/run.sh            run everything
#   bash tests/cli/run.sh -v         also show stdout/stderr of failing tests
#
# No Docker daemon, no bats, no new dependency: bash + coreutils + yq (mikefarah
# v4, the same yq the CLI itself needs; preinstalled on GitHub's ubuntu runners).
# `tests/cli/fake-docker` is placed first on PATH; it records every call so the
# tests can assert the exact docker argument vector the CLI builds. The CLI is
# executed unmodified (no test hooks).
#
# Each test gets a fresh sandbox (HOME, config dir, fake-docker state, PATH).
# Exit status: 0 = all green, 1 = failures, 2 = the harness itself cannot run.
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
TF=$ROOT/t-forward
VERBOSE=""
[ "${1:-}" = "-v" ] && VERBOSE=1

die_harness() { printf 'run.sh: %s\n' "$*" >&2; exit 2; }

[ -f "$TF" ] || die_harness "CLI not found: $TF"
[ -x "$TF" ] || die_harness "CLI is not executable: $TF"
VERSION=$(sed -n 's/^VERSION="\(.*\)"$/\1/p' "$TF" | head -n 1)
[ -n "$VERSION" ] || die_harness "cannot read VERSION from $TF"

YQ_BIN=${YQ:-$(command -v yq || true)}
[ -n "$YQ_BIN" ] || die_harness "yq (mikefarah v4) is required; set YQ=/path/to/yq"
"$YQ_BIN" --version 2>&1 | grep -q mikefarah || die_harness "$YQ_BIN is not mikefarah yq v4"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/tf-cli-test.XXXXXX") || die_harness "mktemp failed"
trap 'rm -rf "$TMP"' EXIT

# ---- hermetic toolbox: the CLI sees only these tools (+ fake docker, real yq)
CORE=$TMP/core; mkdir -p "$CORE"
for t in bash env sed tr grep cat head tail cut basename dirname readlink mktemp rm mkdir chmod \
         stat cp mv find sleep wc ls touch id sort awk; do
    p=$(command -v "$t" 2>/dev/null)
    case "$p" in /*) ln -s "$p" "$CORE/$t" ;; *) die_harness "required tool missing: $t" ;; esac
done
YQDIR=$TMP/yqdir; mkdir -p "$YQDIR"; ln -s "$YQ_BIN" "$YQDIR/yq"
REAL_ID=$(command -v id)

# a prompt (`ask`) reads /dev/tty: detach from the terminal so a regression
# there fails fast instead of hanging a developer's shell, and cap the runtime
ISOLATE=()
command -v timeout >/dev/null 2>&1 && ISOLATE+=(timeout -k 2 90)
command -v setsid >/dev/null 2>&1 && ISOLATE+=(setsid -w)

# ------------------------------------------------------------------ framework
TESTS=0 ASSERTIONS=0 FAILS=0 CUR="" CUR_FAILED=0 SBN=0
SB="" RC=0 STDIN_FILE="" TF_ENV=() NO_DOCKER="" NO_YQ=""
CALL=() LAST=""

flush_failure() {
    if [ "$CUR_FAILED" -eq 1 ] && [ -n "$VERBOSE" ] && [ -n "$SB" ]; then
        printf '       --- stdout ---\n'; sed 's/^/       /' "$SB/out" 2>/dev/null | head -n 20
        printf '       --- stderr ---\n'; sed 's/^/       /' "$SB/err" 2>/dev/null | head -n 20
    fi
}

begin() { # begin DESCRIPTION  -> fresh sandbox
    flush_failure
    TESTS=$((TESTS + 1)); CUR=$1; CUR_FAILED=0; SBN=$((SBN + 1))
    SB=$TMP/sb$SBN; STDIN_FILE=""; TF_ENV=(); NO_DOCKER=""; NO_YQ=""; RC=0
    mkdir -p "$SB/bin" "$SB/dbin" "$SB/home" "$SB/cfg/conf.d" "$SB/work" \
             "$SB/fake/calls" "$SB/fake/containers" "$SB/fake/networks"
    printf 'hunter2\n' >"$SB/pw"; chmod 600 "$SB/pw"          # a valid password file
    printf 'FAKEKEY\n' >"$SB/key"; chmod 600 "$SB/key"       # a valid ssh key file
    ln -s "$HERE/fake-docker" "$SB/dbin/docker"
    # deterministic `id -g` (the CLI shares the auth dir with the host group)
    printf '#!/bin/sh\n[ "$1" = "-g" ] && { echo "${FAKE_GID:-4242}"; exit 0; }\nexec %s "$@"\n' "$REAL_ID" >"$SB/bin/id"
    chmod +x "$SB/bin/id"
}

check() { # check DESCRIPTION COMMAND...   (the command's success = pass)
    local desc=$1; shift
    ASSERTIONS=$((ASSERTIONS + 1))
    if "$@"; then return 0; fi
    FAILS=$((FAILS + 1))
    [ "$CUR_FAILED" -eq 1 ] || printf 'FAIL - %s\n' "$CUR"
    CUR_FAILED=1
    printf '       x %s   [last: tf %s]\n' "$desc" "$LAST"
    return 1
}

# run the CLI inside the sandbox; sets RC, $SB/out, $SB/err
tf() {
    LAST="$*"
    local path=$SB/bin
    [ -n "$NO_DOCKER" ] || path=$path:$SB/dbin
    [ -n "$NO_YQ" ] || path=$path:$YQDIR
    path=$path:$CORE
    ( cd "$SB/work" && ${ISOLATE[@]+"${ISOLATE[@]}"} env -i PATH="$path" HOME="$SB/home" \
        T_FORWARD_CONFIG_DIR="$SB/cfg" FAKE_DOCKER_DIR="$SB/fake" \
        T_FORWARD_CONNECT_TIMEOUT=3 LC_ALL=C TERM=dumb \
        ${TF_ENV[@]+"${TF_ENV[@]}"} "$TF" "$@" ) \
        <"${STDIN_FILE:-/dev/null}" >"$SB/out" 2>"$SB/err"
    RC=$?
}

conf() { cat >"$SB/cfg/conf.d/$1.yaml"; chmod 600 "$SB/cfg/conf.d/$1.yaml"; }
seed() { # seed NAME STATUS [LABEL-NAME] [TAGS]  -> a pre-existing container tf-NAME
    printf 'status=%s\nname=%s\ntags=%s\nauthdir=\n' "${2:-running}" "${3:-$1}" "${4:-}" \
        >"$SB/fake/containers/tf-$1"
}
secret() { printf '%s\n' "$2" >"$SB/$1"; chmod "${3:-600}" "$SB/$1"; }

# ---- assertions on the last run
rc()        { check "exit code is $1 (was $RC)" test "$RC" -eq "$1"; }
out_has()   { check "stdout has: $1" grep -qF -- "$1" "$SB/out"; }
err_has()   { check "stderr has: $1" grep -qF -- "$1" "$SB/err"; }
out_lacks() { check "stdout lacks: $1" bash -c '! grep -qF -- "$1" "$2"' _ "$1" "$SB/out"; }
err_lacks() { check "stderr lacks: $1" bash -c '! grep -qF -- "$1" "$2"' _ "$1" "$SB/err"; }
out_empty() { check "stdout is empty" test ! -s "$SB/out"; }
err_empty() { check "stderr is empty" test ! -s "$SB/err"; }
out_match() { check "stdout matches /$1/" grep -qE -- "$1" "$SB/out"; }
err_match() { check "stderr matches /$1/" grep -qE -- "$1" "$SB/err"; }
exists()    { check "exists: ${1#"$SB"/}" test -e "$1"; }
absent()    { check "absent: ${1#"$SB"/}" test ! -e "$1"; }
mode_is()   { check "mode of ${1#"$SB"/} is $2" test "$(stat -c %a "$1")" = "$2"; }

# ---- assertions on the recorded docker calls
load_call() { CALL=(); local a; while IFS= read -r -d '' a; do CALL+=("$a"); done <"$1"; }
find_call() { # find_call WORD...  -> first call starting with these words (sets CALL)
    local f i ok
    for f in "$SB"/fake/calls/*; do
        [ -f "$f" ] || continue
        load_call "$f"; ok=1; i=0
        for w in "$@"; do
            [ "${CALL[$i]:-}" = "$w" ] || { ok=0; break; }
            i=$((i + 1))
        done
        [ "$ok" -eq 1 ] && return 0
    done
    CALL=(); return 1
}
count_calls() { local n=0 f; for f in "$SB"/fake/calls/*; do [ -f "$f" ] && n=$((n + 1)); done; echo "$n"; }
has_call()  { check "docker $* was called" find_call "$@"; }
no_call()   { check "docker $* was NOT called" not find_call "$@"; }
calls_are() { check "docker was called $1 time(s) (was $(count_calls))" test "$(count_calls)" -eq "$1"; }
arg_pair() { local i; for ((i = 0; i + 1 < ${#CALL[@]}; i++)); do
                 [ "${CALL[$i]}" = "$1" ] && [ "${CALL[$i + 1]}" = "$2" ] && return 0; done; return 1; }
arg_is()    { local a; for a in "${CALL[@]}"; do [ "$a" = "$1" ] && return 0; done; return 1; }
call_pair() { check "run has $1 $2" arg_pair "$1" "$2"; }
call_env()  { check "run has -e $1" arg_pair -e "$1"; }
call_arg()  { check "run has arg: $1" arg_is "$1"; }
call_noarg() { check "run has no standalone arg: $1" not arg_is "$1"; }
call_last() { check "last docker argument is $1" test "${CALL[${#CALL[@]} - 1]}" = "$1"; }
call_regex_arg() { local a; for a in "${CALL[@]}"; do [[ "$a" =~ $1 ]] && return 0; done; return 1; }
snap_has()  { check "auth dir snapshot has /$1/" grep -qE -- "$1" "$SB/fake/snapshot"; }
no_secret_in_calls() { check "'$1' never appears in a docker call" not grep -rqaF -- "$1" "$SB/fake/calls"; }
not() { ! "$@"; }
forget_calls() { rm -rf "$SB/fake/calls"; mkdir -p "$SB/fake/calls"; }

# the common ad-hoc local tunnel used by many tests
ADHOC_LOCAL=(up --type local --name rel --forward 8080:db.internal:5432)

# ================================================================== help etc.

begin "help: -h / --help print usage and exit 0 without touching docker"
tf --help;  rc 0; out_has "Usage:"; out_has "t-forward $VERSION"; err_empty; calls_are 0
tf -h;      rc 0; out_has "t-forward up NAME"
out_has "t-forward completion bash|zsh"; out_has "--forward LOCAL:RHOST:RPORT"

begin "help: works with neither docker nor yq installed"
NO_DOCKER=1; NO_YQ=1; tf --help; rc 0; out_has "Usage:"; err_empty

begin "version: -V / --version print the VERSION from the script"
tf -V;        rc 0; check "stdout is exactly 't-forward $VERSION'" test "$(cat "$SB/out")" = "t-forward $VERSION"
tf --version; rc 0; out_has "t-forward $VERSION"; calls_are 0

begin "unknown command: usage on stdout, error on stderr, exit 1"
tf frobnicate; rc 1; err_has "ERROR: unknown command: frobnicate"; out_has "Usage:"

begin "unknown command with shell metacharacters is echoed, not executed"
tf 'x;touch PWNED;$(touch PWNED2)'; rc 1; err_has 'unknown command: x;touch PWNED;$(touch PWNED2)'
absent "$SB/work/PWNED"; absent "$SB/work/PWNED2"

begin "missing arguments: up / down / code / logs / completion"
tf up;                 rc 1; err_has "usage: t-forward up NAME [NAME...]"
tf down;               rc 1; err_has "usage: t-forward down NAME...|all"
tf code;               rc 1; err_has "usage: t-forward code NAME CODE"
tf code only-a-name;   rc 1; err_has "usage: t-forward code NAME CODE"
tf logs;               rc 1; err_has "usage: t-forward logs [-f] NAME"
tf completion;         rc 1; err_has "usage: t-forward completion bash|zsh"
tf completion fish;    rc 1; err_has "usage: t-forward completion bash|zsh"
tf events -f;          rc 1; err_has "follow (-f) needs a single tunnel name"
no_call run

begin "unknown targets: logs / events / code on a tunnel that does not exist"
tf logs nope;          rc 1; err_has "'nope' has no container (never connected?)"
tf events nope;        rc 1; err_has "'nope' has no container"
tf code nope 123456;   rc 1; err_has "'nope' has no running container"

begin "completion: prints scripts and needs neither docker nor yq"
NO_DOCKER=1; NO_YQ=1
tf completion bash; rc 0; out_has "complete -F _t_forward t-forward"; out_has "verbs=\"up down code status list logs events build completion"
tf completion zsh;  rc 0; out_has "#compdef t-forward"; out_has "compdef _t_forward t-forward"

begin "completion: both scripts parse in their shell and list every verb"
tf completion bash; rc 0; cp "$SB/out" "$SB/comp.bash"
check "bash completion script passes bash -n" bash -n "$SB/comp.bash"
for v in up down code status list logs events build completion; do
    out_has "$v"
done

# ============================================================ preflight errors

begin "preflight: docker not installed"
NO_DOCKER=1; tf list; rc 1; err_has "ERROR: docker not found. Install Docker Desktop or OrbStack."; out_empty
tf up x; rc 1; err_has "docker not found"

begin "preflight: yq not installed"
NO_YQ=1; tf list; rc 1; err_has "ERROR: yq not found. Install it: brew install yq"
tf up x;  rc 1; err_has "yq not found"; no_call run

begin "preflight: daemon down / permission denied -> clear error, nothing started"
TF_ENV=(FAKE_DOCKER_INFO_FAIL=1)
tf status; rc 1; err_has "ERROR: docker daemon is not running. Start Docker Desktop / OrbStack."; out_empty
no_call run; no_call network create
TF_ENV=(FAKE_DOCKER_INFO_FAIL=1 "FAKE_DOCKER_INFO_MSG=permission denied while trying to connect to the Docker daemon socket")
tf "${ADHOC_LOCAL[@]}"; rc 1; err_has "docker daemon is not running"; no_call run

# =================================================== list / status / no config

begin "list: no configs -> hint, exit 0"
tf list; rc 0; out_has "no VPNs configured. Drop YAML files into $SB/cfg/conf.d/<name>.yaml"
tf;      rc 0; out_has "no VPNs configured"

begin "status: nothing running"
tf status; rc 0; out_has "no active t-forward connections"; has_call ps -aq --filter label=t-forward

begin "status: a running container with tags and ports"
seed office running "Office VPN" "prod eu"
tf status; rc 0
out_has "Office VPN  running  (since 2026-01-02 03:04:05)  [prod eu]"
out_has "    10001/tcp -> 127.0.0.1:55001"

begin "list: configured tunnels, ACTIVE marker, bad config flagged, perms tightened"
conf alpha <<'EOF'
name: Alpha VPN
vpn: {server: a.example.com, protocol: fortinet, user: u}
socks: 1080
EOF
conf bravo <<'EOF'
name: Bravo SSH
type: ssh
ssh: {host: 10.0.0.9, user: bob}
hosts:
  - ip: 10.1.1.1
    forwards:
      - {remote: 22, local: 2222}
      - {remote: 80}
EOF
conf broken <<'EOF'
type: vpn
vpn: {protocol: fortinet, user: u}
EOF
chmod 644 "$SB/cfg/conf.d/alpha.yaml"
seed alpha running
tf list; rc 0
out_match '^ +1  alpha +Alpha VPN +vpn +fortinet +false +0 +1080 +ACTIVE'
out_match '^ +2  bravo +Bravo SSH +ssh +10\.0\.0\.9 +false +2 +- +-'
out_has "(invalid config"
err_has "broken: SERVER is required"
err_has "alpha.yaml had mode 644; tightened to 600"
mode_is "$SB/cfg/conf.d/alpha.yaml" 600

begin "--config: file, directory and missing path"
mkdir -p "$SB/other"
printf 'name: Solo\ntype: local\nhosts:\n  - ip: 10.0.0.1\n    forwards:\n      - {remote: 80, local: 8080}\n' >"$SB/other/solo.yaml"
chmod 600 "$SB/other/solo.yaml"
tf --config "$SB/other/solo.yaml" list; rc 0; out_has "solo"
tf --config "$SB/other" list;           rc 0; out_has "Solo"
tf --config "$SB/nowhere" list;         rc 1; err_has "--config: no such file or directory: $SB/nowhere"

# ================================================== name resolution (up/down)

begin "up NAME: unknown name lists the known ones; exact, index and substring resolve"
conf alpha-one <<'EOF'
type: local
hosts: [{ip: 10.0.0.1, forwards: [{remote: 80, local: 8080}]}]
EOF
conf alpha-two <<'EOF'
type: local
hosts: [{ip: 10.0.0.2, forwards: [{remote: 80, local: 8081}]}]
EOF
tf up nope;   rc 1; err_has "no VPN 'nope'. Known: alpha-one, alpha-two"; no_call run
tf up alpha;  rc 1; err_has "'alpha' is ambiguous: alpha-one alpha-two"; no_call run
tf up 3;      rc 1; err_has "no VPN '3'"
tf up two;    rc 0; out_has "Connected: 'alpha-two'"; has_call run; call_pair --name tf-alpha-two
tf up 1;      rc 0; out_has "Connected: 'alpha-one'"

begin "down: not connected, by name, by index/substring, and 'all'"
conf alpha-one <<'EOF'
type: local
hosts: [{ip: 10.0.0.1, forwards: [{remote: 80, local: 8080}]}]
EOF
tf down ghost; rc 0; out_has "'ghost' is not connected"; no_call rm
seed alpha-one running
tf down alpha; rc 0; out_has "disconnected 'alpha'"
has_call rm -f tf-alpha-one; has_call network rm tf-net-alpha-one
seed alpha-one running
tf down 1;     rc 0; out_has "disconnected '1'"; has_call rm -f tf-alpha-one
seed x1 running; seed x2 running; : >"$SB/fake/networks/tf-net-x1"
tf down all;   rc 0; out_has "disconnected all (2)"; has_call inspect -f '{{.Name}}' tf-x1
has_call network rm tf-net-x1
absent "$SB/fake/containers/tf-x1"; absent "$SB/fake/containers/tf-x2"

# =================================================== argument validation (up)

begin "up: unknown option and ad-hoc without enough to derive a name"
tf up --bogus;              rc 1; err_has "unknown option for 'up': --bogus"
tf up --type vpn --user bob; rc 1; err_has "ad-hoc up needs --name or enough to derive one"
no_call run

begin "up: required fields per tunnel type"
tf up --type vpn --name t1 --server s.example --user u;            rc 1; err_has "t1: PROTOCOL is required"
tf up --type vpn --name t2 --server s.example --protocol gp;       rc 1; err_has "t2: VPN_USER is required"
tf up --type vpn --name t3 --user u --protocol gp;                 rc 1; err_has "t3: SERVER is required"
tf up --type vpn --name t4 --server s --user u --protocol bogus;   rc 1; err_has "t4: unsupported PROTOCOL 'bogus'"
tf up --type weird --name t5;                                      rc 1; err_has "t5: unsupported TYPE 'weird' (vpn | ssh | local)"
tf up --ssh-host h.example --name t6;                              rc 1; err_has "t6: SSH_USER is required"
tf up --type local --name t7;                                      rc 1; err_has "t7: local tunnel needs FORWARDS and/or SOCKS"
tf up --type vpn --name t8 --server s --user u --protocol ipsec;   rc 1; err_has "ipsec needs vpn.psk"
no_call run

begin "up: values starting with '-' are rejected (option injection)"
tf up --server '--script=/tmp/x' --user u --protocol gp --name t9;  rc 1; err_has "SERVER must not start with '-'"
tf up --server s --user '-oProxyCommand=id' --protocol gp --name t10; rc 1; err_has "VPN_USER must not start with '-'"
tf up --server s --user u --protocol gp --authgroup '--csd-wrapper=x' --name t11; rc 1; err_has "AUTHGROUP must not start with '-'"
tf up --ssh-host '-oProxyCommand=id' --ssh-user u --name t12;        rc 1; err_has "SSH_HOST must not start with '-'"
tf up --ssh-host h --ssh-user '-x' --name t13;                       rc 1; err_has "SSH_USER must not start with '-'"
tf up --ssh-host h --ssh-user u --ssh-jump '-oProxyCommand=id' --ssh-key /nonexistent --name t14
rc 1; err_has "SSH_JUMP must not start with '-'"
no_call run

begin "up: port validation (ssh port, socks, forwards)"
P=(--password-file "$SB/pw")
tf up --ssh-host h --ssh-user u --ssh-port abc --name t15 "${P[@]}";   rc 1; err_has "t15: SSH_PORT must be numeric ('abc')"
tf up --ssh-host h --ssh-user u --ssh-port '22;id' --name t16 "${P[@]}"; rc 1; err_has "SSH_PORT must be numeric"
tf up --type local --name t17 --forward 80:h:22 --socks abc;           rc 1; err_has "t17: SOCKS must be a port number, 'any', or 'false' ('abc')"
tf up --type local --name t18 --forward 8080;                          rc 1; err_has "invalid forward '8080' (expected LOCAL:RHOST:RPORT)"
tf up --type local --name t19 --forward 8080:host:http;                rc 1; err_has "invalid forward '8080:host:http'"
tf up --type local --name t20 --forward 8080:host:;                    rc 1; err_has "invalid forward"
tf up --type local --name t21 --forward web:host:80;                   rc 1; err_has "invalid forward local part in 'web:host:80'"
tf up --type local --name t22 --forward '8080:h,fork:80';              rc 1; err_has "invalid forward remote host 'h,fork'"
tf up --type local --name t23 --forward '8080:h;id:80';                rc 1; err_has "invalid forward remote host 'h;id'"
tf up --type local --name t24 --forward 'evil:8080:h:80';              rc 1; err_has "invalid forward bind 'evil' in 'evil:8080:h:80'"
tf up --type local --name t25 --forward '-p:80:h:80';                  rc 1; err_has "invalid forward bind"
no_call run

begin "up: config-file validation (each bad config is refused, nothing started)"
mkbad() { conf "$1"; }
mkbad badyaml <<'EOF'
name: [unterminated
EOF
mkbad ssh-noport <<'EOF'
type: ssh
ssh: {host: h, user: u, port: "22x", key: /k}
EOF
mkbad ssh-jump-nokey <<'EOF'
type: ssh
ssh: {host: h, user: u, jump: ["10.0.0.1"]}
EOF
mkbad socks-bad <<'EOF'
type: local
socks: abc
hosts: [{ip: 10.0.0.1, forwards: [{remote: 80, local: 8080}]}]
EOF
mkbad ipsec-ikev <<'EOF'
vpn: {server: s.example, protocol: ipsec, user: u, password: p, psk: k, ikev: 3}
EOF
mkbad ipsec-prop <<'EOF'
vpn: {server: s.example, protocol: ipsec, user: u, password: p, psk: k, ike_proposal: "aes256 sha1"}
EOF
mkbad ipsec-nopass <<'EOF'
vpn: {server: s.example, protocol: ipsec, user: u, psk: k}
EOF
mkbad vpn-dash <<'EOF'
vpn: {server: "-evil", protocol: gp, user: u}
EOF
mkbad type-bogus <<'EOF'
type: telnet
EOF
tf up badyaml;         rc 1; err_has "invalid YAML, skipping: badyaml"
tf up ssh-noport;      rc 1; err_has "ssh-noport: SSH_PORT must be numeric ('22x')"
tf up ssh-jump-nokey;  rc 1; err_has "ssh-jump-nokey: SSH_JUMP (multi-hop) needs SSH_KEY"
tf up socks-bad;       rc 1; err_has "socks-bad: SOCKS must be a port number"
tf up ipsec-ikev;      rc 1; err_has "ipsec-ikev: vpn.ikev must be 1 or 2 ('3')"
tf up ipsec-prop;      rc 1; err_has "ipsec-prop: invalid vpn.ike_proposal for ipsec"
tf up ipsec-nopass;    rc 1; err_has "ipsec-nopass: ipsec needs vpn.password"
tf up vpn-dash;        rc 1; err_has "vpn-dash: SERVER must not start with '-'"
tf up type-bogus;      rc 1; err_has "type-bogus: unsupported TYPE 'telnet'"
no_call run

begin "up: several names, one bad -> the good one still comes up, exit 1"
conf good <<'EOF'
type: local
hosts: [{ip: 10.0.0.1, forwards: [{remote: 80, local: 8080}]}]
EOF
tf up nope good; rc 1; err_has "no VPN 'nope'"; out_has "Connected: 'good'"; has_call run

begin "secret files: missing, empty, loose mode, stdin"
tf up --type local --name t --forward 80:h:22 --password-file "$SB/absent"; rc 1; err_has "cannot read secret file: $SB/absent"
: >"$SB/empty"; chmod 600 "$SB/empty"
tf up --type local --name t --forward 80:h:22 --password-file "$SB/empty"; rc 1; err_has "secret file is empty: $SB/empty"
STDIN_FILE=$SB/empty; tf up --type local --name t --forward 80:h:22 --password-stdin; rc 1; err_has "--password-stdin: no password on stdin"
no_call run
secret loose hunter2 644
tf up --type local --name t --forward 80:h:22 --password-file "$SB/loose"; rc 0
err_has "loose has mode 644; a secret file should be 600"
secret good hunter2 600
tf up --type local --name t2 --forward 81:h:22 --password-file "$SB/good"; rc 0; err_lacks "a secret file should be 600"

begin "no tty and no password: refuses with 'empty password' instead of hanging"
if [ "${#ISOLATE[@]}" -ge 2 ] || command -v setsid >/dev/null 2>&1; then
    tf up --server vpn.example.com --user bob --protocol fortinet --name nopw
    rc 1; err_has "empty password"; no_call run
else
    check "setsid unavailable: skipped" true
fi

# ======================================================= docker argument vector

begin "docker run: the full argument vector of an unprivileged local tunnel"
tf "${ADHOC_LOCAL[@]}"; rc 0
out_has "Connecting 'rel' (local relay)..."; out_has "Connected: 'rel'"
out_has "  forward  127.0.0.1:55001  ->  db.internal:5432"
has_call info; has_call image inspect -f '{{.Config.User}}' t-forward:latest
has_call network inspect tf-net-rel
has_call network create --label t-forward=1 tf-net-rel
has_call run
check "run starts with: run -d --name tf-rel --network tf-net-rel" \
    test "${CALL[*]:0:6}" = "run -d --name tf-rel --network tf-net-rel"
call_pair --user 10001:10001; call_arg --cap-drop=ALL; call_pair --security-opt no-new-privileges
call_pair --group-add 4242
call_pair -l t-forward=1; call_pair -l t-forward.name=rel; call_pair -l t-forward.type=local
call_pair -l t-forward.tags=
call_env TUNNEL_TYPE=local; call_env "FORWARDS=10001|db.internal|5432;"; call_env SOCKS=false
call_env KEEP_AUTH=false; call_env CONNECT_TIMEOUT=3; call_env SERVERCERT_TOFU=false
call_pair -p 127.0.0.1:8080:10001
call_last t-forward:latest
check "auth dir mounted at /auth from the state dir" call_regex_arg "^$SB/cfg/\\.auth/auth-rel:/auth\$"
check "non-root image: no NET_ADMIN" not arg_is --cap-add=NET_ADMIN
check "non-root image: no tun device" not arg_is --device
snap_has '^\. 770$'
absent "$SB/cfg/.auth/auth-rel"
mode_is "$SB/cfg/.auth" 700

begin "docker run: published addresses (any / BIND:PORT / T_FORWARD_BIND / socks)"
TF_ENV=(T_FORWARD_BIND=0.0.0.0)
tf up --type local --name pub --forward any:db:5432 --forward 10.9.8.7:9000:db:22 --forward 0.0.0.0:any:db:80 --socks any
rc 0; has_call run
call_pair -p 0.0.0.0::10001; call_pair -p 10.9.8.7:9000:10002; call_pair -p 0.0.0.0::10003
call_pair -p 127.0.0.1::1080; call_env SOCKS=true
call_env "FORWARDS=10001|db|5432;10002|db|22;10003|db|80;"
begin "docker run: default bind is loopback; fixed socks port"
tf up --type local --name lo --forward any:db:5432 --socks 1081
rc 0; has_call run; call_pair -p 127.0.0.1::10001; call_pair -p 127.0.0.1:1081:1080; call_env SOCKS=true

begin "docker run: --restart resolves 'any' to a concrete port and keeps the auth dir"
tf up --type local --name rs --forward any:db:5432 --socks any --restart
rc 0; has_call run
check "forward port is a concrete 5-digit port" call_regex_arg '^127\.0\.0\.1:[0-9]{5}:10001$'
check "socks port is a concrete 5-digit port" call_regex_arg '^127\.0\.0\.1:[0-9]{5}:1080$'
call_pair --restart unless-stopped; call_env KEEP_AUTH=true
out_has "restart  unless-stopped"
exists "$SB/cfg/.auth/auth-rs"; mode_is "$SB/cfg/.auth/auth-rs" 770

begin "docker run: --restart with manual TOTP is refused"
conf totp-restart <<'EOF'
vpn: {server: s.example, protocol: fortinet, user: u, password: p, totp: true}
EOF
tf up --restart totp-restart; rc 1; err_has "RESTART needs unattended auth"; no_call run
conf totp-restart2 <<'EOF'
vpn: {server: s.example, protocol: fortinet, user: u, password: p, totp: true}
restart: true
EOF
tf up totp-restart2; rc 1; err_has "RESTART needs unattended auth"; no_call run

begin "docker run: vpn tunnel from a config file (root + NET_ADMIN, every env var)"
conf office <<'EOF'
name: Office VPN
tags: [prod, eu]
vpn:
  server: vpn.example.com
  protocol: anyconnect
  user: alice
  password: s3cret-pw
  authgroup: staff
  totp: true
  totp_secret: JBSWY3DPEHPK3PXP
  no_dtls: true
hosts:
  - ip: 10.1.1.5
    forwards:
      - {remote: 22, local: 2222}
      - {remote: 80}
socks: 1080
EOF
tf up office; rc 0
has_call run
call_pair --user 0; call_arg --cap-add=NET_ADMIN; call_pair --device /dev/net/tun
check "vpn run has no --cap-drop" not arg_is --cap-drop=ALL
check "vpn run has no --group-add" not arg_is --group-add
call_pair -l t-forward.name=office
call_pair -l "t-forward.tags=prod eu"; call_pair -l t-forward.type=vpn
call_env TUNNEL_TYPE=vpn; call_env VPN_SERVER=vpn.example.com; call_env VPN_PROTOCOL=anyconnect
call_env VPN_USER=alice; call_env AUTHGROUP=staff; call_env TOTP=true; call_env NO_DTLS=true
call_env "FORWARDS=10001|10.1.1.5|22;10002|10.1.1.5|80;"; call_env SOCKS=true
call_pair -p 127.0.0.1:2222:10001; call_pair -p 127.0.0.1::10002; call_pair -p 127.0.0.1:1080:1080
no_secret_in_calls "s3cret-pw"; no_secret_in_calls "JBSWY3DPEHPK3PXP"
snap_has '^password 600 s3cret-pw\|$'; snap_has '^totp_secret 600 base32:JBSWY3DPEHPK3PXP$'; snap_has '^\. 700$'
absent "$SB/cfg/.auth/auth-office"

begin "docker run: shell metacharacters stay ONE argument (values never reach a shell)"
INJ_USER='alice; touch PWNED $(touch PWNED2) `touch PWNED3`'
tf up --server vpn.example.com --user "$INJ_USER" --protocol gp --authgroup 'g "q" '"'"'s'"'"' && x' \
   --password-file "$SB/pw" --name 'My VPN;$(id)' --tags 'a;b $(c)'
rc 0; has_call run
call_env "VPN_USER=$INJ_USER"
call_env "AUTHGROUP=g \"q\" 's' && x"
call_pair -l 't-forward.name=My VPN;$(id)'
call_pair -l 't-forward.tags=a;b $(c)'
call_pair --name tf-my-vpn-id; call_pair --network tf-net-my-vpn-id
for f in PWNED PWNED2 PWNED3; do absent "$SB/work/$f"; absent "$ROOT/$f"; done

begin "docker run: newline in a value cannot smuggle a second docker option"
tf up --server $'vpn.example.com\n--privileged' --user u --protocol gp --password-file "$SB/pw" --name nl
rc 0; has_call run
call_env $'VPN_SERVER=vpn.example.com\n--privileged'
check "no standalone --privileged argument" not arg_is --privileged

begin "container/network names are slugified; path traversal in --name stays in the state dir"
tf up --type local --name '../../etc/Passwd' --forward 80:h:22
rc 0; has_call run
call_pair --name tf-etc-passwd; call_pair --network tf-net-etc-passwd
check "auth dir is inside the state dir" call_regex_arg "^$SB/cfg/\\.auth/auth-etc-passwd:/auth\$"
absent "$SB/etc"; absent "$ROOT/etc"

begin "ssh tunnel: key copied into the auth dir, jump hops, port, strict host key"
conf hop <<EOF
type: ssh
name: Via bastion
ssh:
  host: 10.0.0.30
  user: usr
  port: 2200
  key: $SB/key
  strict_host_key: true
  jump:
    - 10.0.0.10
    - {host: 10.0.0.20, user: admin, port: 2222}
hosts: [{ip: 10.0.0.40, forwards: [{remote: 5432, local: 5433}]}]
EOF
tf up hop; rc 0; has_call run
call_env TUNNEL_TYPE=ssh; call_env SSH_HOST=10.0.0.30; call_env SSH_USER=usr; call_env SSH_PORT=2200
call_env SSH_STRICT_HOST_KEY=true; call_env "SSH_JUMP=10.0.0.10 admin@10.0.0.20:2222"
call_pair -p 127.0.0.1:5433:10001
call_pair --user 10001:10001
snap_has '^ssh_key 660 FAKEKEY\|$'
out_has "Connecting 'hop' (ssh usr@10.0.0.30:2200)..."

begin "ssh tunnel: missing key file / password via the secret file, never in docker args"
tf up --ssh-host h.example --ssh-user u --ssh-key "$SB/nokey" --name sk
rc 1; err_has "'sk': SSH_KEY not found: $SB/nokey"; no_call run; absent "$SB/cfg/.auth/auth-sk"
secret pw2 'p@ss w0rd; id'
tf up --ssh-host h.example --ssh-user u --password-file "$SB/pw2" --name sp
rc 0; no_secret_in_calls 'p@ss w0rd'; snap_has '^password 660 p@ss w0rd; id\|$'
tf down sp
tf up --ssh-host h.example --ssh-user u --password 'inline-pw' --name sq
rc 0; err_has "--password puts the secret in the process list"; no_secret_in_calls 'inline-pw'

begin "stored TOFU pin is enforced, otherwise --tofu asks the container to learn one"
conf pinned <<'EOF'
vpn: {server: s.example, protocol: fortinet, user: u, password: p, tofu: true}
EOF
tf up pinned; rc 0; has_call run; call_env SERVERCERT_TOFU=true; call_env SERVERCERT=
mkdir -p "$SB/cfg/pins"; printf 'pin-sha256:AbC+/=\n' >"$SB/cfg/pins/pinned"
tf down pinned; forget_calls
tf up pinned; rc 0
out_has "Using the stored certificate pin for 'pinned' (pin-sha256:AbC+/=)"
has_call run; call_env SERVERCERT=pin-sha256:AbC+/=; call_env SERVERCERT_TOFU=false

begin "pin learned by the container is stored 600 in a 700 dir; garbage is ignored"
conf learn <<'EOF'
vpn: {server: s.example, protocol: fortinet, user: u, password: p, tofu: true}
EOF
TF_ENV=("FAKE_DOCKER_LEARN_PIN=pin-sha256:Zm9vYmFy+/=")
tf up learn; rc 0
out_has "pinned    pin-sha256:Zm9vYmFy+/="
check "pin file content" test "$(cat "$SB/cfg/pins/learn")" = "pin-sha256:Zm9vYmFy+/="
mode_is "$SB/cfg/pins/learn" 600; mode_is "$SB/cfg/pins" 700
tf down learn
rm -f "$SB/cfg/pins/learn"
TF_ENV=("FAKE_DOCKER_LEARN_PIN=not a pin; touch PWNED")
tf up learn; rc 0; absent "$SB/cfg/pins/learn"; out_lacks "pinned"; absent "$SB/work/PWNED"

begin "ssh host keys are stored per tunnel and seeded into the next connect"
TF_ENV=("FAKE_DOCKER_KNOWN_HOSTS=h.example ssh-ed25519 AAAAFAKE")
tf up --ssh-host h.example --ssh-user u --password-file "$SB/pw" --name kh; rc 0
exists "$SB/cfg/known_hosts/kh"; mode_is "$SB/cfg/known_hosts/kh" 600
tf down kh
TF_ENV=()
tf up --ssh-host h.example --ssh-user u --password-file "$SB/pw" --name kh; rc 0
snap_has '^known_hosts 660 h\.example ssh-ed25519 AAAAFAKE\|$'

begin "ipsec: psk goes to the auth dir only; strongSwan env passed through"
conf ipsec <<'EOF'
vpn:
  server: gw.example.com
  protocol: ipsec
  user: u
  password: xauth-pw
  psk: the-psk
  ikev: 2
  ike_proposal: aes256-sha256-modp2048
  esp_proposal: aes256-sha256
  local_id: client@example.com
  lifetime: 8h
EOF
tf up ipsec; rc 0; has_call run
call_env IKE_VERSION=2; call_env IKE_PROPOSAL=aes256-sha256-modp2048; call_env ESP_PROPOSAL=aes256-sha256
call_env IPSEC_LOCALID=client@example.com; call_env IPSEC_LIFETIME=8h
snap_has '^psk 600 the-psk$'; no_secret_in_calls the-psk; no_secret_in_calls xauth-pw

begin "privilege handling: old root image, rootless daemon and host gid 0"
conf s <<EOF
type: ssh
ssh: {host: h.example, user: u, key: $SB/key}
EOF
TF_ENV=("FAKE_DOCKER_IMG_USER=")
tf up s; rc 0
err_has "image t-forward:latest still runs as root (built before the non-root change); run 't-forward build' to update it"
has_call run; call_pair --user 0; call_arg --cap-add=NET_ADMIN; call_pair --device /dev/net/tun
tf down s; forget_calls
TF_ENV=("FAKE_DOCKER_SECOPTS=[name=seccomp,profile=builtin name=rootless]")
tf up s; rc 0; err_empty; has_call run
call_pair --user 0; call_arg --cap-drop=ALL; call_pair --security-opt no-new-privileges
check "rootless: no --group-add" not arg_is --group-add
check "rootless: no NET_ADMIN" not arg_is --cap-add=NET_ADMIN
tf down s; forget_calls
TF_ENV=(FAKE_GID=0)
tf up s; rc 0; has_call run
call_pair --user 0; call_arg --cap-drop=ALL
check "gid 0 host: no --group-add" not arg_is --group-add
tf down s; forget_calls
TF_ENV=("FAKE_DOCKER_IMG_USER=root")
tf up s; rc 0; err_has "still runs as root"

# ============================================================ run-time outcomes

begin "already connected: no second container"
seed rel running
tf "${ADHOC_LOCAL[@]}"; rc 0; out_has "'rel' is already connected. Use: t-forward down rel"; no_call run

begin "stale (exited) container is removed before reconnecting"
seed rel exited
tf "${ADHOC_LOCAL[@]}"; rc 0
has_call rm -f tf-rel; has_call run; out_has "Connected: 'rel'"

begin "docker run fails: error shown, container/network/auth dir cleaned up"
TF_ENV=(FAKE_DOCKER_RUN_FAIL=1)
tf "${ADHOC_LOCAL[@]}"; rc 1
err_has "ERROR: docker run failed for 'rel': docker: Error response from daemon"
err_has "port is already allocated"
has_call rm -f tf-rel; has_call network rm tf-net-rel; absent "$SB/cfg/.auth/auth-rel"

begin "container exits during connect: logs are shown, everything torn down"
TF_ENV=(FAKE_DOCKER_RUN_MODE=exited "FAKE_DOCKER_LOG_TEXT=auth failed for alice")
tf "${ADHOC_LOCAL[@]}"; rc 1
err_has "WARNING: 'rel' failed to connect. Last log lines:"; err_has "  | auth failed for alice"
has_call logs --tail 15 tf-rel; has_call rm -f tf-rel; has_call network rm tf-net-rel
absent "$SB/cfg/.auth/auth-rel"

begin "--no-prompt: hands off to 'code' (exit 3), then 'code' validates and delivers"
conf tot <<'EOF'
vpn: {server: s.example, protocol: fortinet, user: u, password: p, totp: true}
EOF
TF_ENV=(FAKE_DOCKER_RUN_MODE=await_code)
tf up --no-prompt tot; rc 3
out_has "'tot' is awaiting a verification code."; out_has "t-forward code tot <CODE>"
exists "$SB/cfg/.auth/auth-tot/awaiting_code"; no_call rm
tf code tot 12;           rc 1; err_has "code looks invalid (expected >=4 alphanumeric chars)"
tf code tot 'ab;touch PWNED'; rc 1; err_has "code looks invalid"; absent "$SB/work/PWNED"
absent "$SB/cfg/.auth/auth-tot/code"
tf code tot 123456;       rc 0; out_has "code delivered to 'tot'"; out_has "'tot' connected"
check "code file holds the code" test "$(cat "$SB/cfg/.auth/auth-tot/code")" = "123456"
rm -f "$SB/cfg/.auth/auth-tot/awaiting_code"
tf code tot 123456;       rc 1; err_has "'tot' is not awaiting a verification code"

# ================================================================ other verbs

begin "logs: plain, -f before and after the name"
seed rel running
tf logs rel;    rc 0; out_has "fake log line"; has_call logs tf-rel
tf logs -f rel; rc 0; has_call logs -f tf-rel
conf rel <<'EOF'
type: local
hosts: [{ip: 10.0.0.1, forwards: [{remote: 80, local: 8080}]}]
EOF
tf logs rel -f; rc 0; has_call logs -f tf-rel

begin "events: levels are tagged; with no name every labelled container is read"
seed rel running
TF_ENV=("FAKE_DOCKER_LOG_TEXT=accepting connection from 1.2.3.4
tunnel is up
password sent
ERROR: boom
plain line")
tf events rel; rc 0
out_match '^conn   accepting connection from 1\.2\.3\.4$'
out_match '^tunnel tunnel is up$'
out_match '^auth   password sent$'
out_match '^error  ERROR: boom$'
out_match '^log    plain line$'
has_call logs --tail 40 tf-rel
tf events;     rc 0; has_call ps -q --filter label=t-forward; out_match '^log    plain line$'
tf events -f rel; rc 0; has_call logs -f --tail 40 tf-rel

begin "build: docker build of the repo dir, tag from T_FORWARD_IMAGE; failure reported"
tf build; rc 0; out_has "built t-forward:latest"
has_call build -t t-forward:latest "$ROOT"
TF_ENV=(T_FORWARD_IMAGE=my/image:dev)
tf build; rc 0; has_call build -t my/image:dev "$ROOT"
TF_ENV=(FAKE_DOCKER_BUILD_FAIL=1)
tf build; rc 1; err_has "ERROR: image build failed"

begin "build: refuses when the Dockerfile is not next to the script"
mkdir -p "$SB/lonely"; cp "$TF" "$SB/lonely/t-forward"
TF=$SB/lonely/t-forward tf build 2>/dev/null
rc 1; err_has "Dockerfile not found next to this script"

begin "image bootstrap: pull the published image, tag it; fall back to a local build"
TF_ENV=(FAKE_DOCKER_NO_IMAGE=1)
tf "${ADHOC_LOCAL[@]}"; rc 0
out_has "Image t-forward:latest not found; pulling asimatasert/t-forward:$VERSION..."
has_call pull asimatasert/t-forward:"$VERSION"; has_call tag asimatasert/t-forward:"$VERSION" t-forward:latest
no_call build -t t-forward:latest "$ROOT"
begin "image bootstrap: pull failure falls back to build; empty HUB image builds directly"
TF_ENV=(FAKE_DOCKER_NO_IMAGE=1 FAKE_DOCKER_PULL_FAIL=1)
tf "${ADHOC_LOCAL[@]}"; rc 0; out_has "pull failed; building locally..."; has_call build -t t-forward:latest "$ROOT"
begin "image bootstrap: T_FORWARD_HUB_IMAGE empty never pulls"
TF_ENV=(FAKE_DOCKER_NO_IMAGE=1 T_FORWARD_HUB_IMAGE=)
tf "${ADHOC_LOCAL[@]}"; rc 0; out_has "Image t-forward:latest not found; building it..."; no_call pull

# =================================================================== summary
flush_failure
printf '\n%d tests, %d assertions, %d failed\n' "$TESTS" "$ASSERTIONS" "$FAILS"
[ "$FAILS" -eq 0 ]
