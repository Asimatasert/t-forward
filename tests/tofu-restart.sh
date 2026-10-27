#!/bin/bash
# Regression test: an openconnect tunnel with `tofu: true` and a restart policy
# must keep enforcing the pin it learned on the first start. After the gateway
# starts presenting a different certificate, restarting the container must be
# refused WITHOUT sending a single request to the gateway.
#
# Needs docker, python3 and openssl on the host. The image under test is built
# beforehand (docker build -t <image> .).
#
# usage: tests/tofu-restart.sh [IMAGE]      (default: t-forward:test)
set -u

IMG=${1:-t-forward:test}
PORT=${TEST_GW_PORT:-18443}
WORK=$(mktemp -d)
NAME="tf-tofu-restart-$$"
GW_PID=""
fails=0

cleanup() {
    [ -z "$GW_PID" ] || kill "$GW_PID" 2>/dev/null
    docker rm -f "$NAME" >/dev/null 2>&1
    docker run --rm -v "$WORK:/w" --entrypoint sh "$IMG" -c 'rm -rf /w/auth' >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

check() { # check DESCRIPTION CONDITION-EXIT-CODE
    if [ "$2" -eq 0 ]; then echo "ok   - $1"; else echo "FAIL - $1"; fails=$((fails + 1)); fi
}

mkcert() { # mkcert NAME
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=gw-$1" \
        -keyout "$WORK/$1.key" -out "$WORK/$1.pem" >/dev/null 2>&1
}

cat >"$WORK/gw.py" <<'EOF'
import http.server, ssl, sys
port, cert, key, logfile = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
class H(http.server.BaseHTTPRequestHandler):
    def _any(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        with open(logfile, "a") as f:
            f.write(self.command + " " + self.path + "\n")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    do_GET = do_POST = do_CONNECT = _any
    def log_message(self, *a):
        pass
srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF

start_gw() { # start_gw CERTNAME
    python3 "$WORK/gw.py" "$PORT" "$WORK/$1.pem" "$WORK/$1.key" "$WORK/gw.log" &
    GW_PID=$!
    sleep 1
}
stop_gw() { kill "$GW_PID" 2>/dev/null; wait "$GW_PID" 2>/dev/null; GW_PID=""; }

wait_exit() { # wait until the container has stopped (max 60s)
    local i=0
    while [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = "true" ] && [ "$i" -lt 60 ]; do
        sleep 1; i=$((i + 1))
    done
}

mkcert a; mkcert b
mkdir -p "$WORK/auth"
printf 'pw\n' >"$WORK/auth/password"
chmod 755 "$WORK/auth"; chmod 644 "$WORK/auth/password"
: >"$WORK/gw.log"

# the env the CLI pins at `docker run` time for a tofu tunnel in restart mode
docker create --name "$NAME" --user 0 --cap-add NET_ADMIN --device /dev/net/tun \
    --add-host host.docker.internal:host-gateway \
    -e TUNNEL_TYPE=vpn -e VPN_SERVER="host.docker.internal:$PORT" -e VPN_PROTOCOL=fortinet \
    -e VPN_USER=u -e SERVERCERT= -e SERVERCERT_TOFU=true -e KEEP_AUTH=true -e CONNECT_TIMEOUT=15 \
    -v "$WORK/auth:/auth" "$IMG" >/dev/null || { echo "cannot create container"; exit 2; }

echo "# first start: gateway presents certificate A"
start_gw a
docker start "$NAME" >/dev/null
wait_exit
learned=$(cat "$WORK/auth/learned_servercert" 2>/dev/null)
case "$learned" in pin-sha256:*) rc=0 ;; *) rc=1 ;; esac
check "first start learned a pin ($learned)" "$rc"
stop_gw

echo "# restart: gateway now presents certificate B (an attacker)"
start_gw b
: >"$WORK/gw.log"
skip=$(docker logs "$NAME" 2>&1 | wc -l)
docker start "$NAME" >/dev/null
wait_exit
stop_gw

if [ ! -s "$WORK/gw.log" ]; then rc=0; else rc=1; fi
check "restart sent 0 requests to the gateway with the changed certificate" "$rc"
if [ "$(cat "$WORK/auth/learned_servercert" 2>/dev/null)" = "$learned" ]; then rc=0; else rc=1; fi
check "the stored pin was not overwritten" "$rc"
second=$(docker logs "$NAME" 2>&1 | tail -n +"$((skip + 1))")
printf '%s\n' "$second" | grep -q 'enforcing the pin learned earlier'; check "restart enforced the learned pin" $?
printf '%s\n' "$second" | grep -q 'trusting pin-sha256' && rc=1 || rc=0
check "restart did not trust a new certificate" "$rc"

if [ "$fails" -ne 0 ]; then echo "$fails check(s) failed"; exit 1; fi
echo "all checks passed"
