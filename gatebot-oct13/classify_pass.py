#!/usr/bin/env python3
"""classify_pass.py v2 -- per-flow classification of passthrough_capture.csv.

Proper STUN detection (magic 0x2112A442 at offset 4, top-2-bit rule),
inner-IPv4 detection (0x45 tunneled), DTLS detection (content type 0x14-0x17
+ version 0xfeff/fefd), else entropy.  Prints first 16 payload bytes.
"""
import csv
import collections
import math
import sys

p = sys.argv[1] if len(sys.argv) > 1 else (
    r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
    r"\captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv")

flows = collections.defaultdict(
    lambda: {"n": 0, "stun": 0, "dtls": 0, "ip4": 0, "ent": 0, "ctl": 0,
             "other": 0, "maxlen": 0, "first": b"", "last": b"",
             "sizes": collections.Counter(), "dir": set()})
n = 0


def classify(app):
    if len(app) < 8:
        return "ctl" if app else "other"
    if app[4:8] == b"\x21\x12\xa4\x42" and (app[0] & 0xC0) == 0:
        return "stun"
    if app[0] in (0x14, 0x15, 0x16, 0x17) and app[1] == 0xFE:
        return "dtls"
    if app[0] == 0x45:
        return "ip4"
    if app[0] in (0xFC, 0xFD) and len(app) == 1:
        return "ctl"
    cnt = collections.Counter(app[:64])
    L = len(app[:64])
    ent = -sum((c / L) * math.log2(c / L) for c in cnt.values())
    if ent > 4.5:
        return "ent"
    return "other"


with open(p, encoding="utf-8", errors="replace") as f:
    for row in csv.reader(f):
        if not row or row[0].startswith("#") or row[0] == "ts_ms":
            continue
        try:
            ts, d, proto, src, sport, dst, dport, iplen, hx = row
        except ValueError:
            continue
        b = bytes.fromhex(hx)
        if len(b) < 28:
            continue
        ihl = (b[0] & 0xF) * 4
        app = b[ihl + 8:] if proto == "udp" else b[ihl + 20:]
        key = (dst, dport, proto)
        e = flows[key]
        e["n"] += 1
        e[classify(app)] += 1
        e["maxlen"] = max(e["maxlen"], len(app))
        e["sizes"][len(app)] += 1
        e["dir"].add(d)
        if not e["first"]:
            e["first"] = app[:16]
        e["last"] = app[:16]
        n += 1

print("rows parsed:", n)
hdr = "%16s %6s %4s %5s %5s %5s %4s %5s %4s %7s  %s"
print(hdr % ("dst", "dport", "proto", "n", "stun", "dtls", "ip4", "ent", "ctl",
              "maxlen", "first16"))
for k in sorted(flows, key=lambda k: -flows[k]["n"])[:24]:
    e = flows[k]
    print(hdr % (k[0], k[1], k[2], e["n"], e["stun"], e["dtls"], e["ip4"],
                 e["ent"], e["ctl"], e["maxlen"], e["first"].hex()))
print()
print("totals:",
      {c: sum(e[c] for e in flows.values())
       for c in ("n", "stun", "dtls", "ip4", "ent", "ctl", "other")})
