#!/usr/bin/env python3
"""peerlink_konami.py -- decode the PeerLink<->Konami coordination handshake.

The gameplay tunnel is LOCAL (hotspot), no TURN relay.  But the phones exchange
hundreds of UDP packets with Google-Cloud Konami servers during the ~1k-packet
establishment phase.  THIS is what the server sees.  Dump/decode those: what
protocol, what strings, request/response pattern, timing vs the local tunnel.

Read-only.  python peerlink_konami.py
"""
import os
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")
Z = ("z1-tiamant-client", "z2-elijah-hotspot-owner")

# Google-Cloud / public (non-local, non-DNS) UDP peers seen in the underlay
def is_local(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") \
        or ip.startswith("172.")


def strings(b, n=4):
    out, cur = [], b""
    for x in b:
        if 32 <= x < 127:
            cur += bytes([x])
        else:
            if len(cur) >= n:
                out.append(cur.decode())
            cur = b""
    if len(cur) >= n:
        out.append(cur.decode())
    return out


for z in Z:
    print("=" * 78)
    print(z)
    print("=" * 78)
    pp = os.path.join(CAP, z, "passthrough_capture.csv")
    # per remote endpoint: list of (ts, dir, len, first16, strings)
    ep = defaultdict(list)
    with open(pp, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or line.startswith("ts_ms,") \
                    or not line.strip():
                continue
            p = line.rstrip("\n").split(",")
            if len(p) < 9 or p[2] != "udp":
                continue
            ts, d, src, sp, dst, dp, iplen, hx = p[0], p[1], p[3], p[4], \
                p[5], p[6], p[7], p[8]
            remote = dst if not is_local(dst) else (src if is_local(src) else None)
            if remote is None or is_local(remote):
                continue
            try:
                b = bytes.fromhex(hx)
            except ValueError:
                continue
            ihl = (b[0] & 0xF) * 4
            payload = b[ihl + 8:]
            rport = dp if not is_local(dst) else sp
            ep[(remote, rport)].append(
                (int(ts), d, len(payload), payload[:16], strings(payload)))

    # report the busiest Konami endpoints
    for (ip, port), pkts in sorted(ep.items(), key=lambda kv: -len(kv[1]))[:4]:
        pkts.sort()
        t0 = pkts[0][0]
        print("  %s:%s  %d packets  span=%.1fs" %
              (ip, port, len(pkts), (pkts[-1][0] - t0) / 1000))
        # direction split
        outn = sum(1 for p in pkts if p[1] == "t")
        print("     out=%d in=%d" % (outn, len(pkts) - outn))
        # timing ramp: packets per second buckets for first 15s
        sec = defaultdict(lambda: [0, 0])
        for (ts, d, ln, head, st) in pkts:
            s = int((ts - t0) // 1000)
            sec[s][0 if d == "t" else 1] += 1
        ramp = ["%d/%d" % tuple(sec[s]) for s in range(min(15, max(sec) + 1))]
        print("     sec(out/in): " + " ".join(ramp))
        # first few packets decoded
        for (ts, d, ln, head, st) in pkts[:6]:
            print("       %s len=%3d head=%s str=%s" %
                  (d, ln, head.hex(), st[:6]))
        print()
    print()
