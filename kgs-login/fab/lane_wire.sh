#!/usr/bin/env bash
# lane_wire.sh — wire the two-phone interception on the real lane host.
#
#   usage: sudo bash lane_wire.sh <container-a> <container-b>
#
# Assumes (created by the lane workflow):
#   docker network fab-a  172.29.1.0/24   container-a = 172.29.1.10
#   docker network fab-b  172.29.2.0/24   container-b = 172.29.2.10
#   fabricated pair: A = 197.210.53.1, B = 197.210.53.2
#
# Installs (routes only through the host — same as the proven smoke):
#   - PREROUTING DNAT: fabricated dst -> peer's real IP  (ports untouched)
#   - POSTROUTING SNAT: real src -> fabricated identity  (ports untouched)
#   - two AF_PACKET fabricator services in PASSTHROUGH mode (enumerate phase;
#     "arm" later flips them to answer + adds the Konami-STUN forward drops).
set -euo pipefail

CA="${1:?container a}"
CB="${1:+${2:?container b}}"
IPA=172.29.1.10
IPB=172.29.2.10
FA=197.210.53.1
FB=197.210.53.2
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IFACE_A=$(ip -o -4 addr show | awk -v a="$IPA.1" '$4==a{print $2; exit}')
IFACE_B=$(ip -o -4 addr show | awk -v a="$IPB.1" '$4==a{print $2; exit}')
[ -n "$IFACE_A" ] && [ -n "$IFACE_B" ] || { echo "bridge ifaces not found"; \
  ip -o -4 addr show; exit 1; }
echo "IFACE_A=$IFACE_A IFACE_B=$IFACE_B"

echo "--- fabricated-pair NAT (host-level, ports untouched) ---"
iptables -t nat -A PREROUTING  -i "$IFACE_A" -p udp -d $FB \
    -j DNAT --to-destination $IPB
iptables -t nat -A PREROUTING  -i "$IFACE_B" -p udp -d $FA \
    -j DNAT --to-destination $IPA
iptables -t nat -A POSTROUTING -o "$IFACE_B" -p udp -s $IPA -d $IPB \
    -j SNAT --to-source $FA
iptables -t nat -A POSTROUTING -o "$IFACE_A" -p udp -s $IPB -d $IPA \
    -j SNAT --to-source $FB

echo "--- fabricator services (passthrough/enumerate phase) ---"
pkill -f stun_service.py 2>/dev/null || true
nohup python3 "$HERE/stun_service.py" --bridge "$IFACE_A" \
    --phone-ip "$IPA" --fab-ip $FA --mode passthrough \
    > /tmp/fab-a.log 2>&1 &
nohup python3 "$HERE/stun_service.py" --bridge "$IFACE_B" \
    --phone-ip "$IPB" --fab-ip $FB --mode passthrough \
    > /tmp/fab-b.log 2>&1 &
sleep 1
grep -q "stun service up" /tmp/fab-a.log && \
  grep -q "stun service up" /tmp/fab-b.log && echo "services up (passthrough)"

iptables -t nat -L PREROUTING -v -x | head -6
iptables -t nat -L POSTROUTING -v -x | head -6
echo "WIRED"
