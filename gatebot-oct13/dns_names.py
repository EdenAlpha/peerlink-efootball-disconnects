#!/usr/bin/env python3
"""dns_names.py -- extract every DNS query name from the PeerLink passthrough
captures (match-2026-09-26).  The DTLS rendezvous servers are raw Google-Cloud
IPs on 30xxx ports; the hostname the phone resolved to find them reveals the
discovery source (a Konami PeerLink/rendezvous service) that chain3 must query.

Read-only.  python dns_names.py
"""
import os
import struct
from collections import Counter

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")
Z = ("z1-tiamant-client", "z2-elijah-hotspot-owner")


def qname(payload):
    """parse a DNS query payload -> qname string or None."""
    if len(payload) < 12:
        return None
    # flags: QR=0 (query)
    flags = struct.unpack(">H", payload[2:4])[0]
    if flags & 0x8000:
        return None                    # response, skip
    qdcount = struct.unpack(">H", payload[4:6])[0]
    if qdcount < 1:
        return None
    i = 12
    labels = []
    while i < len(payload):
        l = payload[i]
        if l == 0:
            i += 1
            break
        if l & 0xC0:                   # compression pointer (shouldn't be in Q)
            break
        labels.append(payload[i + 1:i + 1 + l].decode("utf-8", "replace"))
        i += 1 + l
    return ".".join(labels) if labels else None


for z in Z:
    print("=" * 70)
    print(z)
    print("=" * 70)
    pp = os.path.join(CAP, z, "passthrough_capture.csv")
    names = Counter()
    with open(pp, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or line.startswith("ts_ms,") \
                    or not line.strip():
                continue
            p = line.rstrip("\n").split(",")
            if len(p) < 9 or p[2] != "udp":
                continue
            dp, hx = p[6], p[8]
            if dp != "53":
                continue
            try:
                b = bytes.fromhex(hx)
            except ValueError:
                continue
            ihl = (b[0] & 0xF) * 4
            payload = b[ihl + 8:]
            n = qname(payload)
            if n:
                names[n] += 1
    # print hostnames, prioritizing anything konami/game/relay/stun/peer-ish
    def score(item):
        n = item[0].lower()
        hot = any(k in n for k in ("konami", "pes", "peer", "relay", "stun",
                                   "turn", "sycom", "game", "match", "session"))
        return (0 if hot else 1, -item[1], n)
    for n, c in sorted(names.items(), key=score):
        mark = "  <==" if any(k in n.lower() for k in
                              ("konami", "pes", "peer", "relay", "stun",
                               "turn", "sycom", "game", "match", "session")) \
            else ""
        print("  %4d  %s%s" % (c, n, mark))
    print()
