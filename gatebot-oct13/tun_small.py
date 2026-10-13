#!/usr/bin/env python3
"""tun_small.py -- are small frames plaintext? entropy by bucket + full dumps."""
import math
import sys
from collections import Counter

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from pcapng_read import read_pcapng                                  # noqa: E402

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def main() -> int:
    pkts = read_pcapng(D + r"\m5\tunnel_capture.pcapng")
    frames = []
    for pkt in pkts:
        if len(pkt) < 42:
            continue
        ip = pkt[14:] if pkt[12:14] == b"\x08\x00" else pkt
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        import struct
        b = ip[ihl + 8:]
        if len(b) < 8 or b[0] != 0 or b[1] != 0:
            continue
        if len(b) >= 20 and b[4:8] == b"\x21\x12\xa4\x42":
            continue
        src = ".".join(str(x) for x in ip[12:16])
        frames.append((src, b))
    print("frames: %d" % len(frames))
    print("\n=== mean byte-entropy of body[8:] by len bucket ===")
    buckets = {}
    for src, b in frames:
        k = "14-30" if len(b) <= 30 else "31-60" if len(b) <= 60 else \
            "61-120" if len(b) <= 120 else "121-300" if len(b) <= 300 \
            else "300+"
        buckets.setdefault(k, []).append(entropy(b[8:]))
    for k in ("14-30", "31-60", "61-120", "121-300", "300+"):
        v = buckets.get(k, [])
        print("  %-7s n=%-6d mean_entropy=%.3f (8.0=max)" % (
            k, len(v), sum(v) / len(v) if v else 0))
    print("\n=== complete small frames (first of each len, ours) ===")
    seen = set()
    for src, b in frames:
        if src != "10.58.176.146" or len(b) in seen or len(b) > 60:
            continue
        seen.add(len(b))
        if len(seen) <= 14:
            print("  %3dB %s" % (len(b), b.hex()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
