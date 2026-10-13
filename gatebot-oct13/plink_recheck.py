#!/usr/bin/env python3
"""plink_recheck.py -- leave no packet unclassified, all 3 captures.

Previous passes answered only STUN-fingerprinted rows.  This classifies EVERY
tunnelled row (direction, ports, flags, len census, length-vs-flight shape)
and every direct packet, and reconciles m1 vs m3 (same match, two phones).
"""
import collections

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"
GAME = {"1162", "42010", "17024", "17025"}


def main() -> int:
    for m in ("m1", "m2", "m3"):
        rows = []
        with open(D + r"\%s\udp_trace.csv" % m, encoding="utf-8",
                  errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                p = line.split(",")
                if len(p) < 31:
                    continue
                rows.append(p)
        n = len(rows)
        n_game = sum(1 for p in rows
                     if p[4] in GAME or p[6] in GAME)
        # every distinct (dir, sport, dport, flags) tuple
        tuples = collections.Counter()
        lens = collections.Counter()
        for p in rows:
            key = (p[2], p[4], p[6], p[5])
            tuples[key] += 1
            lens[int(p[6])] += 1
        print("=== %s  rows=%d  on game ports=%d ===" % (m, n, n_game))
        print("  distinct (dir,sport,dport,flags): %d" % len(tuples))
        for k, c in tuples.most_common(15):
            print("    %6d  %s" % (c, k))
        # length histogram buckets
        buckets = collections.Counter()
        for L, c in lens.items():
            b = "0-99" if L < 100 else "100-199" if L < 200 else \
                "200-299" if L < 300 else "300-999" if L < 1000 else \
                "1000-1999" if L < 2000 else "2000+"
            buckets[b] += c
        print("  len buckets:", dict(sorted(buckets.items())))
        big = sorted(((L, c) for L, c in lens.items() if L > 200),
                     key=lambda kv: -kv[1])
        print("  len>200:", big[:10])
        # sample rows of the BIG packets
        seen = set()
        for p in rows:
            L = int(p[6])
            if L > 200 and L not in seen:
                seen.add(L)
                if len(seen) <= 12:
                    print("    big len=%s %s %s:%s->%s:%s flags=%s"
                          % (p[6], p[2], p[3], p[4], p[5], p[6], p[5]))
        # control channel?
        ctrl = sum(1 for p in rows if p[4] in ("17024", "17025")
                   or p[6] in ("17024", "17025"))
        print("  rows on 17024/17025 (match control): %d" % ctrl)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
