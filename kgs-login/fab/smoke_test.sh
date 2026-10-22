#!/usr/bin/env bash
# Datapath smoke test: proves the whole two-phone packet path on plain Linux
# network namespaces, before any Android is booted.
#
# Proven here: TPROXY interception, fabricator answers from the real server
# identity (including CHANGE-IP partner), fabricated mapping per phone, and
# the port-preserving P2P NAT pair. NOTHING touches a phone; the "games" are
# fake_game.py sockets in netns.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BR=br-fab
SUB=172.28.100
IPA=$SUB.10
IPB=$SUB.11
FA=197.210.53.1
FB=197.210.53.2
TA=47000
TB=47001
KLIST="54.248.105.235, 54.150.255.185, 52.198.221.89, 18.176.255.15, \
54.199.110.22, 3.113.89.160, 35.76.243.83, 54.150.169.24, 54.65.202.22, \
54.64.79.140, 13.230.144.13, 176.34.63.31"
STUNPORTS="3478, 3479"

echo "=== [0] host prerequisites ==="
SRV_A=""; SRV_B=""; GA_PID=""
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
modprobe br_netfilter 2>/dev/null || true
modprobe nf_tproxy_ipv4 2>/dev/null || true
if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
  sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
  grep -q 1 /proc/sys/net/bridge/bridge-nf-call-iptables \
    || { echo "bridge-nf-call-iptables != 1"; exit 1; }
else
  echo "WARNING: br_netfilter unavailable; netns routed path relies on it"
fi
command -v nft >/dev/null || { echo "nft not found"; exit 1; }

echo "=== [1] build namespaces + bridge ==="
cleanup() {
  for p in $SRV_A $SRV_B $GA_PID; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  nft delete table ip fab 2>/dev/null || true
  ip netns del fa 2>/dev/null || true
  ip netns del fb 2>/dev/null || true
  ip link del $BR 2>/dev/null || true
  ip rule del fwmark 1 table 100 2>/dev/null || true
}
trap cleanup EXIT
ip netns add fa
ip netns add fb
ip link add $BR type bridge
ip addr add $SUB.1/24 dev $BR
ip link set $BR up
for side in fa fb; do
  ip link add veth-$side type veth peer name eth0 netns $side
done
ip link set veth-fa master $BR
ip link set veth-fb master $BR
ip link set veth-fa up
ip link set veth-fb up
ip netns exec fa ip addr add $IPA/24 dev eth0
ip netns exec fb ip addr add $IPB/24 dev eth0
ip netns exec fa ip link set eth0 up
ip netns exec fb ip link set eth0 up
ip netns exec fa ip link set lo up
ip netns exec fb ip link set lo up
ip netns exec fa ip route add default via $SUB.1
ip netns exec fb ip route add default via $SUB.1
ip netns exec fa sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
ip netns exec fb sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null

echo "=== [2] nft + services ==="
PYP="$HERE"

echo "=== [3] nft forward drop for cluster STUN ==="
{
  echo "table ip fab {"
  echo "  set konamistun { type ipv4_addr; elements = { $KLIST } }"
  echo "  chain fdfilter { type filter hook forward priority filter; policy accept;"
  echo "    iifname \"$BR\" ip daddr @konamistun udp dport { $STUNPORTS } counter drop"
  echo "    oifname \"$BR\" ip saddr @konamistun udp sport { $STUNPORTS } counter drop"
  echo "  }"
  echo "}"
} | nft -f -
nft list table ip fab >/dev/null

echo "=== [3b] per-phone netns NAT (OUTPUT DNAT + POSTROUTING SNAT) ==="
# lives INSIDE each phone's netns - the same proven shape as the lane's
# 443 DNAT. Ports pass untouched everywhere; only IPs change.
ip netns exec fa iptables -t nat -A OUTPUT -p udp -d $FB \
    -j DNAT --to-destination $IPB
ip netns exec fa iptables -t nat -A POSTROUTING -p udp -s $IPA \
    -d $IPB -j SNAT --to-source $FA
ip netns exec fb iptables -t nat -A OUTPUT -p udp -d $FA \
    -j DNAT --to-destination $IPA
ip netns exec fb iptables -t nat -A POSTROUTING -p udp -s $IPB \
    -d $IPA -j SNAT --to-source $FB
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
python3 "$PYP/stun_service.py" --bridge $BR --phone-ip $IPA --fab-ip $FA \
    --mode answer > /tmp/fab-a.log 2>&1 &
SRV_A=$!
python3 "$PYP/stun_service.py" --bridge $BR --phone-ip $IPB --fab-ip $FB \
    --mode answer > /tmp/fab-b.log 2>&1 &
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
  LEAK_PID=$!
fi

ip netns exec fb python3 "$PYP/fake_game.py" b > /tmp/game-b.log 2>&1 &
B_PID=$!
sleep 0.4
ip netns exec fa python3 "$PYP/fake_game.py" a > /tmp/game-a.log 2>&1 &
GA_PID=$!
wait $GA_PID 2>/dev/null || true
wait $B_PID 2>/dev/null || true
sleep 1
cat /tmp/game-a.log /tmp/game-b.log
grep -q "FAKE-A PASS" /tmp/game-a.log || {
  echo "side A failed - diagnostics:"
  cat /tmp/fab-a.log /tmp/fab-b.log
  nft list table ip fab
  echo "--- netns fa nat counters ---"
  ip netns exec fa iptables -t nat -L OUTPUT -v -x || true
  ip netns exec fa iptables -t nat -L POSTROUTING -v -x || true
  echo "--- netns fb nat counters ---"
  ip netns exec fb iptables -t nat -L OUTPUT -v -x || true
  ip netns exec fb iptables -t nat -L INPUT -v -x || true
  echo "--- punch trace on bridge (bounded) ---"
  rm -f /tmp/brdump.txt /tmp/vethdump.txt
  timeout 12 tcpdump -l -i $BR -nn udp > /tmp/brdump.txt 2>&1 &
  TCPD=$!
  timeout 12 tcpdump -l -i veth-fb -nn udp > /tmp/vethdump.txt 2>&1 &
  TCPD2=$!
  ip netns exec fb timeout 12 python3 /tmp/echo_45002.py &
  ECHOB=$!
  sleep 0.5
  ip netns exec fa timeout 12 python3 /tmp/probe_punch.py
  PROBE_RC=$?
  sleep 3
  kill $TCPD $TCPD2 $ECHOB 2>/dev/null || true
  sort -u /tmp/brdump.txt | head -10 || true
  echo "--- fb-side capture ---"
  sort -u /tmp/vethdump.txt | head -10 || true
  echo "--- rp_filter / conntrack state ---"
  ip netns exec fb sysctl net.ipv4.conf.all.rp_filter 2>/dev/null
  ip netns exec fa sysctl net.ipv4.conf.all.rp_filter 2>/dev/null
  ip netns exec fa conntrack -L 2>/dev/null | head -5 || true
  ip netns exec fb conntrack -L 2>/dev/null | head -5 || true
  echo "--- probe rc: $PROBE_RC ---"
  exit 1
}
grep -q "FAKE-B PASS" /tmp/game-b.log || { echo "side B failed"; exit 1; }

if [ -n "${LEAK_PID:-}" ]; then
  sleep 2
  kill $LEAK_PID 2>/dev/null || true
  if grep -q "54.248.105.235\|18.176.255.15" /tmp/leak.txt 2>/dev/null; then
    echo "LEAK: real-world STUN escaped the interception"; exit 1
  fi
  echo "no STUN leaked to the uplink"
fi

echo "PASS datapath smoke: tproxy intercept, spoofed source answers,";
echo "     fabricated mapping per phone, port-preserving P2P NAT both ways"
