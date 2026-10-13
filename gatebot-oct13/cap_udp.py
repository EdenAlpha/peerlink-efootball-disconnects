"""What does the in-game UDP plane look like during the match?
Split the z2 capture by flow and per-minute volume, so we can see
whether the phone keeps a steady UDP heartbeat with the PEER (P2P)
versus bursts with servers (STUN/DTLS/TURN)."""
import csv
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
       r"\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv")

rows = []
with open(CAP, newline="", encoding="latin1") as f:
    for row in csv.DictReader(r for r in f if not r.startswith("#")):
        rows.append(row)

t0 = int(rows[0]["ts_ms"])
flows = defaultdict(lambda: {"n": 0, "bytes": 0, "first": None, "last": None,
                             "sizes": defaultdict(int)})
for r in rows:
    if r["proto"] != "udp":
        continue
    key = (r["dir"], r["dst"], r["dport"])
    fl = flows[key]
    ts = int(r["ts_ms"])
    fl["n"] += 1
    fl["bytes"] += int(r["ip_len"] or 0)
    fl["first"] = ts if fl["first"] is None else min(fl["first"], ts)
    fl["last"] = ts if fl["last"] is None else max(fl["last"], ts)
    fl["sizes"][len(r["payload_hex"]) // 2] += 1

print("UDP flows (dir, dst, dport)  -- sorted by first appearance")
print("%-4s %-18s %-7s %6s %8s %9s %9s  %s"
      % ("dir", "dst", "dport", "pkts", "bytes", "t+first", "t+last", "pkt sizes"))
for (d, dst, dp), fl in sorted(flows.items(), key=lambda kv: kv[1]["first"]):
    span = (fl["last"] - fl["first"]) / 1000.0
    top = sorted(fl["sizes"].items(), key=lambda kv: -kv[1])[:5]
    print("%-4s %-18s %-7s %6d %8d %9.1f %9.1f  %s  span=%.0fs"
          % (d, dst, dp, fl["n"], fl["bytes"],
             (fl["first"] - t0) / 1000.0, (fl["last"] - t0) / 1000.0,
             ",".join("%d:%d" % (s, c) for s, c in top), span))
