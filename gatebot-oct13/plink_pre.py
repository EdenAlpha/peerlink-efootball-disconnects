#!/usr/bin/env python3
"""plink_pre.py -- pre-kickoff big packets, direct-punch bytes, m2 fate."""
import sys

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"
T0 = 182400.0


def main() -> int:
    print("=== m1 pre-kickoff packets >400B (rel_s, dir, len) ===")
    n = 0
    for line in open(D + r"\m1\udp_trace.csv", encoding="utf-8",
                     errors="replace"):
        if line.startswith("#"):
            continue
        p = line.split(",")
        if len(p) < 31:
            continue
        try:
            rel = float(p[9])
        except ValueError:
            continue
        if rel < T0 and int(p[6]) > 400:
            print("  t=%7.1fs %-3s len=%s" % (rel / 1000.0, p[2], p[6]))
            n += 1
    print("  total: %d" % n)

    print("\n=== direct-punch full bytes (internet side, 0x080b/0x090b) ===")
    for line in open(D + r"\m1\passthrough_capture.csv", encoding="utf-8",
                     errors="replace"):
        if line.startswith("#"):
            continue
        p = line.split(",")
        if len(p) < 9 or p[2] != "udp" or p[6] != "1162":
            continue
        pkt = bytes.fromhex(p[8])
        ihl = (pkt[0] & 0xF) * 4
        body = pkt[ihl + 8:]
        print("  %s:%s -> %s:%s len=%d" % (p[3], p[4], p[5], p[6], len(body)))
        print("  " + body.hex())

    print("\n=== m2 match_log tail (why no gameplay) ===")
    with open(D + r"\m2\match_log.txt", encoding="utf-8",
              errors="replace") as f:
        lines = f.readlines()
    for ln in lines[-12:]:
        clean = "".join(c for c in ln if 32 <= ord(c) < 127).strip()
        print("  " + clean[:150])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
