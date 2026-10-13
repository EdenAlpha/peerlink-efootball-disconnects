#!/usr/bin/env python3
"""peerlink_analyze.py -- decode the PeerLink tunnel capture (match-2026-09-26).

The user observed the tunnel packet count ramping 8 -> 20 -> 100 -> 200 -> ~1k
BEFORE kickoff then ~27 pps DURING the match.  udp_trace.csv is a per-packet
classification trace (flags: stun|peerFab|tunnel|fromPeer|inject|...); it has
no payload but has timing/len/flow.  passthrough_capture.csv has full payload
hex for internet-side traffic (STUN/relay/DNS).  Together they show what the
PeerLink session actually is and whether a Konami server is in the path.

Read-only.  python peerlink_analyze.py
"""
import csv
import os
from collections import Counter, defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")
Z = ("z1-tiamant-client", "z2-elijah-hotspot-owner")

for z in Z:
    print("=" * 78)
    print(z)
    print("=" * 78)
    tp = os.path.join(CAP, z, "udp_trace.csv")

    # ---- udp_trace: flags, timing, the establishment ramp ----
    flags = Counter()
    flows = Counter()          # (sport,dport,dir) -> n
    rows = []
    hdr = None
    with open(tp, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("# wifi_truth_trace"):
                hdr = line.strip()
            if line.startswith("#") or not line.strip():
                continue
            p = line.rstrip("\n").split(",")
            # sender_id,seq,dir,ipver,flow_hash,flags,len,sport,dport,rel_ms,...
            if len(p) < 10:
                continue
            try:
                seq = int(p[1])
            except ValueError:
                continue
            dirn = p[2]
            fl = p[5]
            ln = int(p[6])
            sport, dport = int(p[7]), int(p[8])
            rel = float(p[9])
            flags[fl] += 1
            flows[(sport, dport, dirn)] += 1
            rows.append((rel, dirn, fl, ln, sport, dport))
    print("  %s" % hdr)
    print("  packets parsed: %d  time span: %.1f s"
          % (len(rows), (rows[-1][0] - rows[0][0]) / 1000 if rows else 0))
    print("  -- flag combinations --")
    for fl, n in flags.most_common():
        print("     %6d  %s" % (n, fl))
    print("  -- top flows (sport,dport,dir) --")
    for (sp, dp, d), n in flows.most_common(6):
        print("     %6d  %s:%d -> :%d  %s" % (n, "out" if d == "out" else "in",
                                             sp, dp, d))

    # the ramp: packets per 100ms bucket from t0
    if rows:
        t0 = rows[0][0]
        bucket = defaultdict(lambda: [0, 0])   # [out, in]
        for (rel, d, fl, ln, sp, dp) in rows:
            b = int((rel - t0) // 100)
            bucket[b][0 if d == "out" else 1] += 1
        print("  -- first 40 x 100ms buckets (out/in) --")
        line = []
        for b in range(40):
            o, i = bucket.get(b, [0, 0])
            line.append("%d/%d" % (o, i))
        print("     " + "  ".join(line))
    print()

# ---- passthrough: what internet endpoints does the phone talk to? ----
print("=" * 78)
print("passthrough_capture: destinations + protocol + STUN/tunnel payloads")
print("=" * 78)
for z in Z:
    pp = os.path.join(CAP, z, "passthrough_capture.csv")
    dsts = Counter()
    protos = Counter()
    stun_payloads = []
    with open(pp, encoding="utf-8", errors="replace") as f:
        rd = csv.DictReader(f)
        for row in rd:
            if row.get("proto") is None:
                continue
            protos[row["proto"]] += 1
            dsts[(row["dst"], row["dport"])] += 1
            # STUN = first 2 bits 00, magic cookie 0x2112A442 at bytes 4..8
            hx = row.get("payload_hex", "")
            if row["proto"] == "udp" and len(hx) >= 32:
                try:
                    b = bytes.fromhex(hx)
                except ValueError:
                    continue
                ihl = (b[0] & 0xF) * 4
                udp = b[ihl:]
                if len(udp) >= 20 and udp[8:12] == b"\x21\x12\xa4\x42":
                    stun_payloads.append((row["dst"], row["dport"],
                                          int.from_bytes(udp[0:2], "big"),
                                          len(udp) - 8))
    print("  %s" % z)
    print("     protos: %s" % dict(protos))
    print("     top dst:")
    for (d, dp), n in dsts.most_common(10):
        print("        %6d  %s:%s" % (n, d, dp))
    print("     STUN packets (magic cookie 0x2112A442): %d" % len(stun_payloads))
    for (d, dp, mt, ln) in stun_payloads[:8]:
        print("        -> %s:%s type=0x%04x len=%d" % (d, dp, mt, ln))
    print()
