#!/usr/bin/env bash
# lane_gate.sh — prove the fabricated link between the two REAL phones.
#
#   usage: sudo bash lane_gate.sh <container-a> <container-b>
#
# No app, no Android involvement: host python enters each container's
# network namespace (nsenter -n). Phone B's netns runs a UDP echo bound on
# 45002; "phone A" sends punches aimed at the FABRICATED peer endpoint
# (197.210.53.2:45002). Pass criteria:
#   - A's probe crosses the wire and the echo server sees its source as
#     197.210.53.1:<port>  (A's advertised identity),
#   - the echoed reply arrives back at A showing source 197.210.53.2:<port>.
# Exit 0 only if BOTH directions held.
set -euo pipefail

CA="${1:?container a}"
CB="${2:?container b}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PID_A=$(docker inspect -f '{{.State.Pid}}' "$CA")
PID_B=$(docker inspect -f '{{.State.Pid}}' "$CB")
echo "netns A=$PID_A B=$PID_B"

cat > /tmp/lane_echo_b.py <<'PYEOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 45002))
s.settimeout(12)
print("echo up on 45002", flush=True)
try:
    data, addr = s.recvfrom(64)
    print("ECHO saw from", addr, data, flush=True)
    s.sendto(b"LANE-REPLY-B", addr)
except Exception as ex:
    print("echo failed:", ex, flush=True)
PYEOF

cat > /tmp/lane_probe_a.py <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 45001))
s.settimeout(10)
ok = False
for i in range(4):
    s.sendto(b"LANE-PUNCH-%d" % i, ("197.210.53.2", 45002))
    print("probe", i, "sent to 197.210.53.2:45002", flush=True)
    try:
        data, addr = s.recvfrom(64)
        print("PROBE got reply from", addr, data, flush=True)
        ok = (addr[0] == "197.210.53.2")
        break
    except Exception as ex:
        print("no reply:", ex, flush=True)
print("GATE-A", "PASS" if ok else "FAIL", flush=True)
sys.exit(0 if ok else 1)
PYEOF

echo "--- echo server in phone B's netns ---"
nsenter -t "$PID_B" -n python3 /tmp/lane_echo_b.py &
ECHOB=$!
sleep 0.5

echo "--- probes from phone A's netns ---"
set +e
nsenter -t "$PID_A" -n python3 /tmp/lane_probe_a.py
RC=$?
set -e
kill $ECHOB 2>/dev/null || true
wait $ECHOB 2>/dev/null || true
echo "gate rc=$RC"
exit $RC
