#!/usr/bin/env python3
"""tun_hdr.py -- header table of every 0x00 frame (m5): seq? class? stream?"""
import struct
import sys
from collections import Counter

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from pcapng_read import read_pcapng                                  # noqa: E402

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"


def main() -> int:
    pkts = read_pcapng(D + r"\m5\tunnel_capture.pcapng")
    rows = []
    for i, pkt in enumerate(pkts):
        if len(pkt) < 42:
            continue
        ip = pkt[14:] if pkt[12:14] == b"\x08\x00" else pkt
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        b = ip[ihl + 8:]
        if len(b) < 8 or b[0] != 0 or b[1] != 0:
            continue
        if len(b) >= 20 and b[4:8] == b"\x21\x12\xa4\x42":
            continue
        src = ".".join(str(x) for x in ip[12:16])
        rows.append((i, src, len(b), b[2], b[3], b[4], b[5], b[6], b[7]))
    print("0x00 frames: %d" % len(rows))
    # per-direction seq check on [2:4] as u16be
    print("\n=== first 30 (idx dir len b2 b3 b4 b5 b6 b7) ===")
    for i, src, L, b2, b3, b4, b5, b6, b7 in rows[:30]:
        print("  #%5d %-15s %4d  %02x %02x %02x %02x %02x %02x" % (
            i, src, L, b2, b3, b4, b5, b6, b7))
    # does [2:4] increment per direction?
    print("\n=== [2:4] be16 runs per direction (first 200 rows) ===")
    last = {}
    breaks = 0
    for i, src, L, b2, b3, b4, b5, b6, b7 in rows[:200]:
        v = (b2 << 8) | b3
        if src in last and v != (last[src] + 1) % 65536:
            breaks += 1
            if breaks <= 8:
                print("  break #%d last=%d now=%d (len %d b4=%02x)" % (
                    i, last[src], v, L, b4))
        last[src] = v
    print("  breaks in first 200: %d" % breaks)
    # byte4 class distribution by len bucket
    print("\n=== byte4 class x len bucket ===")
    c = Counter()
    for _, _, L, _, _, b4, _, _, _ in rows:
        bkt = "small<100" if L < 100 else "mid<300" if L < 300 else "big"
        c[(b4, bkt)] += 1
    for k in sorted(c):
        print("  b4=0x%02x %-9s %d" % (k[0], k[1], c[k]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
