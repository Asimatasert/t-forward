#!/bin/bash
# Regression test: nothing on the far side of a vpn tunnel may reach the socat
# forwards or the (unauthenticated) SOCKS proxy. Both listen on the eth0
# ADDRESS, and Linux delivers a packet for a local address no matter which
# interface it arrives on, so the address bind alone does not keep a VPN
# gateway / peer out: it only has to send to the eth0 address through the tunnel.
#
# With net.ipv4.ip_forward=1 in the container the same peer could also route
# packets through the container to other hosts on the Docker side. The filter
# that closes both must not break the tunnel's own return traffic, so that is
# checked too.
#
# No VPN server and no outside network are involved. The real entrypoint runs in
# vpn mode with the privileges the CLI gives it; only `openconnect` is replaced
# by a stand-in that builds a real tun0 to a "peer" container (socat TUN over
# UDP, addresses from 192.0.2.0/30):
#
#   client ---eth0--- [tunnel container] ---tun0 ~~~ tun0--- peer
#   (published side)                                 (far side: the VPN gateway,
#                                                     192.0.2.2 and 198.51.100.1)
#
# The client is the legitimate user (it reaches eth0 the way a published port
# does). The peer plays the gateway and a host behind it:
#   (a) legitimate use: the client reaches a far-side service through a forward
#       and through the SOCKS proxy. Towards 192.0.2.2 the tunnel container
#       uses its tun0 address as source; towards 198.51.100.1 it uses its eth0
#       address (as with a gateway that assigns no tunnel address of its own),
#       so those replies come back through the tunnel addressed to the very
#       address the filter protects.
#   (b) attack: the peer routes TCP for the tunnel container's eth0 address
#       into the tunnel and tries the listeners. Must fail.
#   (c) attack: the peer routes UDP for the client into the tunnel, i.e. asks
#       the tunnel container to forward it. Must not arrive.
#
# Needs docker on the host. The image under test is built beforehand
# (docker build -t <image> .).
#
# usage: tests/tunnel-isolation.sh [IMAGE]      (default: t-forward:test)
set -u

IMG=${1:-t-forward:test}
PFX="${TEST_NAME_PREFIX:-tf-tunnel-iso}-$$"
TUNNEL="$PFX-tunnel"; PEER="$PFX-peer"; CLIENT="$PFX-client"; NET="$PFX-net"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/$PFX.XXXXXX") || exit 2
FAR1=192.0.2.2      # the peer's tunnel address
FAR2=198.51.100.1   # a second far-side address, reached with the eth0 address as source
fails=0

cleanup() {
    docker rm -f "$TUNNEL" "$PEER" "$CLIENT" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    docker run --rm --name "$PFX-cleanup" -v "$WORK:/w" --user 0 --entrypoint sh "$IMG" \
        -c 'rm -rf /w/auth' >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

check() { # check DESCRIPTION CONDITION-EXIT-CODE
    if [ "$2" -eq 0 ]; then echo "ok   - $1"; else echo "FAIL - $1"; fails=$((fails + 1)); fi
}
expect() { # expect DESCRIPTION WANTED GOT
    if [ "$2" = "$3" ]; then check "$1" 0; else check "$1 (got '$3')" 1; fi
}
refused() { # refused DESCRIPTION GOT   (anything received = failure)
    if [ -z "$2" ]; then check "$1" 0; else check "$1 (got '$2')" 1; fi
}

ip_of() { # ip_of CONTAINER
    docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1" 2>/dev/null
}

# SOCKS5 greeting (version 5, one method, "no authentication"); microsocks
# answers 05 00. Prints the answer in hex, nothing when the connection fails.
socks_hello() { # socks_hello CONTAINER
    docker exec "$1" timeout 5 bash -c \
        'exec 3<>"/dev/tcp/$0/1080" && printf "\005\001\000" >&3 && head -c 2 <&3 | od -An -tx1' \
        "$eth_ip" 2>/dev/null | tr -d ' \n'
}

# what a far-side service on port 7777 sends, fetched through the SOCKS proxy
# (CONNECT to an IPv4 address). The whole conversation is read by one reader
# and checked afterwards: method answer 05 00, CONNECT answer 05 00 + 8 bytes,
# then the service's line. Prints "far-ok" for exactly that, otherwise the raw
# hex (nothing when the proxy is unreachable).
socks_fetch() { # socks_fetch CONTAINER FAR-ADDRESS
    local hex
    hex=$(docker exec "$1" timeout 8 bash -c '
        exec 3<>"/dev/tcp/$0/1080" || exit 1
        IFS=. read -r a b c d <<<"$1"
        printf "\005\001\000" >&3
        sleep 0.5
        printf "\005\001\000\001$(printf "\\\\%03o" "$a" "$b" "$c" "$d")\036\141" >&3
        od -An -tx1 <&3' "$eth_ip" "$2" 2>/dev/null | tr -d ' \n')
    case "$hex" in
        05000500????????????????6661722d6f6b0a) echo far-ok ;;
        *) echo "$hex" ;;
    esac
}

# first line relayed by a forward, nothing on failure
forward_banner() { # forward_banner CONTAINER PORT
    docker exec "$1" timeout 8 bash -c 'exec 3<>"/dev/tcp/$0/$1" && head -n 1 <&3' \
        "$eth_ip" "$2" 2>/dev/null
}

# Stand-in for openconnect: a tun0 whose packets travel to the peer over UDP.
# Nothing else of the entrypoint is replaced.
cat >"$WORK/openconnect" <<'EOF'
#!/bin/bash
socat "UDP:${TEST_VPN_PEER}:5555" TUN:192.0.2.1/30,tun-name=tun0,iff-up,iff-no-pi &
i=0   # the first packet also brings up the peer's end of the tunnel
until ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 30 ] || exit 1
    sleep 0.2
done
# a far-side host that is reached with the eth0 address as the tunnel source
eth=$(ip -4 addr show eth0 | awk '/inet /{print $2}' | cut -d/ -f1)
ip route add "${TEST_VPN_FAR2}/32" dev tun0 src "$eth" || exit 1
echo "stand-in openconnect: tun0 is up"
wait
EOF
chmod 755 "$WORK/openconnect"
mkdir -p "$WORK/auth"
printf 'pw\n' >"$WORK/auth/password"
chmod 755 "$WORK/auth"; chmod 644 "$WORK/auth/password"

docker network create "$NET" >/dev/null || { echo "cannot create the test network"; exit 2; }

# published side: the legitimate client, which is also the target of one
# forward and of the forwarding attempt (c)
docker run -d --name "$CLIENT" --network "$NET" --entrypoint socat "$IMG" \
    TCP-LISTEN:8080,fork,reuseaddr 'SYSTEM:echo tfwd-ok' >/dev/null \
    || { echo "cannot start the client container"; exit 2; }
docker exec -d "$CLIENT" socat -u UDP-RECV:9999 OPEN:/tmp/udp.log,creat,append
# far side: the other end of the tunnel, with a service on both of its addresses
# (rp_filter is loosened in this container only: it accepts tunnel packets
# whose source is the tunnel container's eth0 address)
docker run -d --name "$PEER" --network "$NET" --user 0 --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.conf.all.rp_filter=2 --entrypoint socat "$IMG" \
    UDP-LISTEN:5555,reuseaddr TUN:192.0.2.2/30,tun-name=tun0,iff-up,iff-no-pi >/dev/null \
    || { echo "cannot start the peer container"; exit 2; }
docker exec "$PEER" ip addr add "$FAR2/32" dev lo || { echo "cannot set up the peer container"; exit 2; }
docker exec -d "$PEER" socat TCP-LISTEN:7777,fork,reuseaddr 'SYSTEM:echo far-ok'
client_ip=$(ip_of "$CLIENT")

# the tunnel container, started the way the CLI starts a vpn tunnel
docker run -d --name "$TUNNEL" --network "$NET" \
    --user 0 --cap-add NET_ADMIN --device /dev/net/tun \
    -e TUNNEL_TYPE=vpn -e VPN_SERVER=gateway.invalid -e VPN_PROTOCOL=fortinet -e VPN_USER=u \
    -e FORWARDS="10001|$client_ip|8080;10002|$FAR1|7777;10003|$FAR2|7777;" -e SOCKS=true \
    -e CONNECT_TIMEOUT=30 -e TEST_VPN_PEER="$(ip_of "$PEER")" -e TEST_VPN_FAR2="$FAR2" \
    -v "$WORK/auth:/auth" -v "$WORK/openconnect:/usr/bin/openconnect:ro" "$IMG" >/dev/null \
    || { echo "cannot start the tunnel container"; exit 2; }

up() { docker logs "$TUNNEL" 2>&1 | grep -q '\[t-forward\] READY' \
           && docker logs "$TUNNEL" 2>&1 | grep -q 'stand-in openconnect: tun0 is up'; }
i=0
until up; do
    [ "$(docker inspect -f '{{.State.Running}}' "$TUNNEL" 2>/dev/null)" = "true" ] && [ "$i" -lt 40 ] || break
    sleep 1; i=$((i + 1))
done
up; rc=$?
check "the tunnel container came up (forwards + SOCKS enabled)" "$rc"
if [ "$rc" -ne 0 ]; then
    docker logs "$TUNNEL" 2>&1 | tail -n 15
    echo "$fails check(s) failed"; exit 1
fi

eth_ip=$(ip_of "$TUNNEL")
echo "# tunnel container: eth0 $eth_ip (published side), tun0 192.0.2.1 (far side)"
echo "# rp_filter all/eth0/tun0: $(docker exec "$TUNNEL" sh -c \
    'cat /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/conf/eth0/rp_filter /proc/sys/net/ipv4/conf/tun0/rp_filter' | tr '\n' ' ')"
docker exec "$TUNNEL" nft list table inet tforward 2>/dev/null | sed 's/^/#   /'
docker exec "$TUNNEL" nft list table inet tforward 2>/dev/null | grep -q 'ct state related meta l4proto icmp accept'
check "the loaded filter accepts related packets for ICMP only" $?
! docker exec "$TUNNEL" nft list table inet tforward 2>/dev/null | grep -q 'ct state related accept'
check "the loaded filter has no catch-all 'ct state related accept'" $?

# The peer sends TCP for the tunnel container's eth0 address into the tunnel
# (everything else, including the tunnel's own UDP transport, stays on eth0).
# The same route carries the replies of (a) that are addressed to it.
docker exec "$PEER" ping -c 1 -W 3 192.0.2.1 >/dev/null 2>&1
check "far-side peer reaches the tunnel endpoint (tun0 address) through the tunnel" $?
docker exec "$PEER" sh -c "ip route add default dev tun0 table 100 && ip rule add to $eth_ip ipproto tcp lookup 100"
docker exec "$PEER" ip route get "$eth_ip" ipproto tcp dport 1080 2>/dev/null | grep -q 'dev tun0 '
check "far-side peer routes TCP for the eth0 address into the tunnel" $?
docker exec "$TUNNEL" ip route get "$FAR2" 2>/dev/null | grep -q "dev tun0 src $eth_ip "
check "the tunnel container uses its eth0 address as source towards $FAR2" $?

echo "# published side (must work)"
expect "client on the published side talks to the SOCKS proxy" 0500 "$(socks_hello "$CLIENT")"
expect "client on the published side uses a forward to a Docker-side target" tfwd-ok "$(forward_banner "$CLIENT" 10001)"

echo "# (a) legitimate traffic through the tunnel (must work, replies included)"
expect "forward to the far side, tun0 address as source" far-ok "$(forward_banner "$CLIENT" 10002)"
expect "forward to the far side, eth0 address as source" far-ok "$(forward_banner "$CLIENT" 10003)"
expect "SOCKS to the far side, tun0 address as source" far-ok "$(socks_fetch "$CLIENT" "$FAR1")"
expect "SOCKS to the far side, eth0 address as source" far-ok "$(socks_fetch "$CLIENT" "$FAR2")"

echo "# (b) far side of the tunnel opens connections to the listeners (must be refused)"
refused "far-side peer cannot talk to the SOCKS proxy" "$(socks_hello "$PEER")"
refused "far-side peer cannot use a forward" "$(forward_banner "$PEER" 10001)"

echo "# (c) far side of the tunnel sends to another host on the Docker side (must not be forwarded)"
udp_send() { # udp_send TEXT -> one datagram from the peer to the client
    docker exec "$PEER" timeout 5 bash -c 'echo "$1" >"/dev/udp/$0/9999"' "$client_ip" "$1" 2>/dev/null
}
udp_log() { docker exec "$CLIENT" cat /tmp/udp.log 2>/dev/null; }
udp_send direct   # control: straight over the Docker network, proves the receiver works
i=0; until udp_log | grep -qx direct || [ "$i" -ge 10 ]; do sleep 0.5; i=$((i + 1)); done
udp_log | grep -qx direct
check "control: the client receives a datagram the peer sends over the Docker network" $?
docker exec "$PEER" ip rule add to "$client_ip" ipproto udp lookup 100
docker exec "$PEER" ip route get "$client_ip" ipproto udp dport 9999 2>/dev/null | grep -q 'dev tun0 '
check "far-side peer routes UDP for the client into the tunnel" $?
for i in 1 2 3; do udp_send through-tunnel; done
sleep 2
refused "the tunnel container does not forward far-side packets to the client" "$(udp_log | grep -v -x direct | sort -u)"

echo "# published side and tunnel still work afterwards"
expect "client on the published side talks to the SOCKS proxy" 0500 "$(socks_hello "$CLIENT")"
expect "SOCKS to the far side, eth0 address as source" far-ok "$(socks_fetch "$CLIENT" "$FAR2")"

if [ "$fails" -ne 0 ]; then echo "$fails check(s) failed"; exit 1; fi
echo "all checks passed"
