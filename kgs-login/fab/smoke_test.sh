#!/usr/bin/env bash
# Datapath smoke test: proves the whole two-phone packet path on plain Linux
# network namespaces, before any Android is booted.
#
# Topology (fully routed; no bridge dependencies):
#   netns fa 172.28.101.10 --(v-fa)-- host 172.28.101.1
#   netns fb 172.28.102.11 --(v-fb)-- host 172.28.102.1
#   host routes between the subnets.
#
# Proven here: AF_PACKET tap + fabricated answers (real server identity,
# RFC 5780 partner semantics), per-phone netns NAT (OUTPUT DNAT to the peer's
# real IP, POSTROUTING SNAT to the fabricated IP; ports untouched), and the
# forward-path isolation of the Konami STUN set. The "games" are fake_game.py
# sockets in the netns. NOTHING touches a phone.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FA=197.210.53.1
FB=197.210.53.2
KLIST="54.248.105.235 54.150.255.185 52.198.221.89 18.176.255.15 54.199.110.22 3.113.89.160 35.76.243.83 54.150.169.24 54.65.202.22 54.64.79.140 13.230.144.13 176.34.63.31"

echo "=== [0] host prerequisites ==="
SRV_A=""; SRV_B=""; GA_PID=""
sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns list >/dev/null 2>&1 || { echo "netns unavailable"; exit 1; }
command -v iptables >/dev/null || { echo "iptables not found"; exit 1; }

cleanup() {
  for p in $SRV_A $SRV_B $GA_PID; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  ip netns del fa 2>/dev/null || true
  ip netns del fb 2>/dev/null || true
}
trap cleanup EXIT

echo "=== [1] build routed namespaces ==="
ip netns add fa
ip netns add fb
ip link add v-fa type veth peer name eth0 netns fa
ip link add v-fb type veth peer name eth0 netns fb
ip addr add 172.28.101.1/24 dev v-fa
ip addr add 172.28.102.1/24 dev v-fb
ip link set v-fa up
ip link set v-fb up
ip netns exec fa ip addr add 172.28.101.10/24 dev eth0
ip netns exec fb ip addr add 172.28.102.11/24 dev eth0
ip netns exec fa ip link set eth0 up
ip netns exec fb ip link set eth0 up
ip netns exec fa ip link set lo up
ip netns exec fb ip link set lo up
ip netns exec fa ip route add default via 172.28.101.1
ip netns exec fb ip route add default via 172.28.102.1
ip netns exec fa sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
ip netns exec fb sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null

# forward the two subnets through the host; docker's DROP policy on runners
# is overwritten by explicit accepts for our veth pairs.
iptables -I FORWARD 1 -i v-fa -o v-fb -j ACCEPT
iptables -I FORWARD 1 -i v-fb -o v-fa -j ACCEPT
iptables -I FORWARD 1 -i v-fa -o eth0 -j ACCEPT
iptables -I FORWARD 1 -i eth0 -o v-fa -j ACCEPT
iptables -I FORWARD 1 -i v-fb -o eth0 -j ACCEPT
iptables -I FORWARD 1 -i eth0 -o v-fb -j ACCEPT

# konami STUN isolation for BOTH directions of BOTH phones
for ip in $KLIST; do
  iptables -A FORWARD -i v-fa -p udp -d "$ip" -j DROP
  iptables -A FORWARD -o v-fa -p udp -s "$ip" -j DROP
  iptables -A FORWARD -i v-fb -p udp -d "$ip" -j DROP
  iptables -A FORWARD -o v-fb -p udp -s "$ip" -j DROP
done

echo "=== [3b] per-phone netns NAT (OUTPUT DNAT + POSTROUTING SNAT) ==="
# lives INSIDE each phone's netns - the same proven shape as the lane's
# 443 DNAT. Ports pass untouched everywhere; only IPs change.
ip netns exec fa iptables -t nat -A OUTPUT -p udp -d $FB \
    -j DNAT --to-destination 172.28.102.11
ip netns exec fa iptables -t nat -A POSTROUTING -p udp -s 172.28.101.10 \
    -d 172.28.102.11 -j SNAT --to-source $FA
ip netns exec fb iptables -t nat -A OUTPUT -p udp -d $FA \
    -j DNAT --to-destination 172.28.101.10
ip netns exec fb iptables -t nat -A POSTROUTING -p udp -s 172.28.102.11 \
    -d 172.28.101.10 -j SNAT --to-source $FB
cat > /tmp/probe_punch.py <<'PYEOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 45011))
s.settimeout(3)
for i in range(4):
    s.sendto(b"PROBE-%d" % i, ("197.210.53.2", 45002))
    print("probe sent", i, flush=True)
    try:
        print("got reply from", s.recvfrom(64), flush=True)
        break
    except Exception as ex:
        print("probe no reply:", ex, flush=True)
PYEOF
cat > /tmp/echo_45002.py <<'PYEOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 45002))
s.settimeout(11)
try:
    while True:
        data, addr = s.recvfrom(64)
        print("echo saw from", addr, data, flush=True)
        s.sendto(b"ECHO", addr)
except Exception as ex:
    print("echo done:", ex, flush=True)
PYEOF

echo "=== [4] start the two fabricator instances (AF_PACKET tap) ==="
python3 "$HERE/stun_service.py" --bridge v-fa --phone-ip 172.28.101.10 \
    --fab-ip $FA --mode answer > /tmp/fab-a.log 2>&1 &
SRV_A=$!
python3 "$HERE/stun_service.py" --bridge v-fb --phone-ip 172.28.102.11 \
    --fab-ip $FB --mode answer > /tmp/fab-b.log 2>&1 &
SRV_B=$!
sleep 1
kill -0 $SRV_A $SRV_B 2>/dev/null || { echo "services died:"; \
  cat /tmp/fab-a.log /tmp/fab-b.log; exit 1; }

echo "=== [5] watch the uplink for leaked STUN ==="
UPLINK=$(ip route show default | awk '{print $5; exit}')
if command -v tcpdump >/dev/null 2>&1 && [ -n "$UPLINK" ]; then
  rm -f /tmp/leak.txt
  timeout 9 tcpdump -q -l -i "$UPLINK" -nn udp and \
    "host 54.248.105.235 or host 18.176.255.15" \
    > /tmp/leak.txt 2>/dev/null &
fi

echo "=== [6] run the fake games ==="
ip netns exec fb python3 "$HERE/fake_game.py" b > /tmp/game-b.log 2>&1 &
B_PID=$!
sleep 0.4
ip netns exec fa python3 "$HERE/fake_game.py" a > /tmp/game-a.log 2>&1 &
GA_PID=$!
wait $GA_PID 2>/dev/null || true
wait $B_PID 2>/dev/null || true
sleep 1
cat /tmp/game-a.log /tmp/game-b.log
grep -q "FAKE-A PASS" /tmp/game-a.log || {
  echo "side A failed - diagnostics:"
  cat /tmp/fab-a.log /tmp/fab-b.log
  echo "--- netns fa nat counters ---"
  ip netns exec fa iptables -t nat -L OUTPUT -v -x || true
  ip netns exec fa iptables -t nat -L POSTROUTING -v -x || true
  echo "--- netns fb nat counters ---"
  ip netns exec fb iptables -t nat -L OUTPUT -v -x || true
  ip netns exec fb iptables -t nat -L INPUT -v -x || true
  exit 1
}
grep -q "FAKE-B PASS" /tmp/game-b.log || {
  echo "side B failed - diagnostics:"
  cat /tmp/fab-b.log /tmp/game-b.log
  ip netns exec fb iptables -t nat -L OUTPUT -v -x || true
  exit 1
}

if [ -n "${LEAK_PID:-}" ]; then
  sleep 2
  kill "${LEAK_PID:-}" 2>/dev/null || true
  if grep -q "54.248.105.235\|18.176.255.15" /tmp/leak.txt 2>/dev/null; then
    echo "LEAK: real-world STUN escaped the interception"; exit 1
  fi
  echo "no STUN leaked to the uplink"
fi

echo "PASS datapath smoke: fabricated answers (binding + CHANGE-IP partner ";
echo "     semantics), per-phone mapping, port-preserving P2P NAT both ways"
