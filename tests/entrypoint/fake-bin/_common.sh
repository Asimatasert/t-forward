# shellcheck shell=bash
# Shared helpers for the fakes in this directory (sourced, never executed).
#
# State lives in $FAKE_STATE (one directory per test):
#   calls/NNNN.<cmd>   one file per call: the argv, NUL-separated (argument
#                      boundaries stay visible to the tests)
#   listening          local ports the fakes pretend to listen on (read by `ss`)
#   signals            "<cmd> TERM" lines: which fake was sent a TERM
#   stop               when present the long-running tunnel fakes exit with the
#                      status written in it (how a test ends a healthy tunnel)
set -u

FS=${FAKE_STATE:?FAKE_STATE not set}
mkdir -p "$FS/calls" "$FS/seq"

# record CMD ARGS... -> calls/NNNN.CMD (the counter is a mkdir, so concurrent
# fakes never share a number)
record() {
    local n=1
    while ! mkdir "$FS/seq/$n" 2>/dev/null; do n=$((n + 1)); done
    printf -v CALLFILE '%s/calls/%04d.%s' "$FS" "$n" "$1"
    printf '%s\0' "$@" >"$CALLFILE"
}

# linger CMD [stoppable] - play a long-running process. It ends when it is sent
# TERM, when its parent (the entrypoint) is gone, or after 60 s, so a fake can
# never outlive its test. A stoppable fake also ends when $FS/stop appears.
linger() {
    local name=$1 stoppable=${2:-} parent=$PPID life=0 rc
    # shellcheck disable=SC2064  # $name is meant to be expanded now
    trap "echo '$name TERM' >>\"\$FS/signals\"; exit 143" TERM
    while kill -0 "$parent" 2>/dev/null && [ "$life" -lt 600 ]; do
        if [ -n "$stoppable" ] && [ -e "$FS/stop" ]; then
            rc=$(cat "$FS/stop")
            exit "${rc:-0}"
        fi
        sleep 0.1 &
        wait $!
        life=$((life + 1))
    done
    exit 0
}
