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

echo "=== [2] policy routing for TPROXY ==="
ip rule add fwmark 1 table 100
ip route add local 0.0.0.0/0 dev lo table 100

echo "=== [3] nft rules (tproxy + port-preserving p2p nat) ==="
{
  echo "table ip fab {"
  echo "  set konamistun { type ipv4_addr; elements = { $KLIST } }"
  echo "  chain pre { type filter hook prerouting priority mangle; policy accept;"
  echo "    iifname \"$BR\" ip saddr $IPA ip daddr @konamistun udp dport { $STUNPORTS } meta mark set 1 counter tproxy ip to :$TA"
  echo "    iifname \"$BR\" ip saddr $IPB ip daddr @konamistun udp dport { $STUNPORTS } meta mark set 1 counter tproxy ip to :$TB"
  echo "  }"
  echo "  chain natpre { type nat hook prerouting priority dstnat; policy accept;"
  echo "    iifname \"$BR\" ip saddr $IPA ip daddr $FB meta l4proto udp counter dnat ip to $IPB"
  echo "    iifname \"$BR\" ip saddr $IPB ip daddr $FA meta l4proto udp counter dnat ip to $IPA"
  echo "  }"
  echo "  chain natpost { type nat hook postrouting priority srcnat; policy accept;"
  echo "    oifname \"$BR\" ip saddr $IPA ip daddr $IPB meta l4proto udp counter snat ip to $FA"
  echo "    oifname \"$BR\" ip saddr $IPB ip daddr $IPA meta l4proto udp counter snat ip to $FB"
  echo "  }"
  echo "}"
} | nft -f -
nft list table ip fab >/dev/null

echo "=== [4] start the two fabricator instances ==="
PYP="$HERE"
python3 "$PYP/stun_service.py" --fab-ip $FA --listen-port $TA --mode answer \
    > /tmp/fab-a.log 2>&1 &
SRV_A=$!
python3 "$PYP/stun_service.py" --fab-ip $FB --listen-port $TB --mode answer \
    > /tmp/fab-b.log 2>&1 &
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
  echo "side A failed - diagnostics:"; cat /tmp/fab-a.log
  nft list table ip fab
  ip rule show; ip route show table 100
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
