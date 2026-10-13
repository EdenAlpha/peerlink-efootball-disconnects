#!/usr/bin/env python3
"""Scan the PeerLink passthrough captures for NTL ReportLog traffic.

The NTL capture facts say the game posts to ReportLog.php with log types
pds/pde (p2p session open/close) and uds/ude (udp session open/close).
If the server uses those to decide a match session exists, never sending
them would read exactly as "session never existed" -> DISCONN_HB.

This only READS the capture; it never sends anything.
"""
import csv
import os
import re
import sys

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")

WANT = re.compile(rb"(ReportLog|GateInfo|\.php|pds|pde|uds|ude)", re.I)


def scan(path, limit=40):
    hits = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        rd = csv.reader(f)
        header = next(rd, [])
        for row in rd:
            joined = "|".join(row)
            low = joined.lower()
            if "reportlog" in low or "gateinfo" in low:
                hits.append(joined)
            elif re.search(r"\bpds\b|\bpde\b|\buds\b|\bude\b", low):
                hits.append(joined)
            if len(hits) >= limit:
                break
    return header, hits


def main():
    for root, _dirs, files in os.walk(CAP):
        for fn in files:
            if not fn.endswith(".csv"):
                continue
            p = os.path.join(root, fn)
            print("=== %s (%d bytes) ===" % (
                os.path.relpath(p, CAP), os.path.getsize(p)))
            try:
                header, hits = scan(p)
            except Exception as e:                                  # noqa: BLE001
                print("  scan failed: %s %s" % (type(e).__name__, e))
                continue
            print("  header: %s" % ",".join(header)[:400])
            print("  hits: %d" % len(hits))
            for h in hits[:12]:
                print("   ", h[:500])
    return 0


if __name__ == "__main__":
    sys.exit(main())
