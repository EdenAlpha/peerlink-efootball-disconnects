#!/usr/bin/env python3
"""Extract the real GateInfo.php request AND its response, byte for byte.

chain3's ntl_gateinfo() gets STATUS:400 from NTL.  The capture has the
exact bytes the real client sent and the exact reply the server gave, so
the difference is knowable rather than guessed.  Read-only.
"""
import os
import re
import sys
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")

REQ_LINE = re.compile(rb"^(GET|POST) ([^ \r\n]+) HTTP/1\.[01]")


def strip_ip(raw):
    if len(raw) < 20 or (raw[0] >> 4) != 4:
        return b""
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or raw[9] != 6 or len(raw) < ihl + 20:
        return b""
    tcp = raw[ihl:]
    off = ((tcp[12] >> 4) & 0x0F) * 4
    if off < 20 or len(tcp) < off:
        return b""
    return tcp[off:]


def flows(path):
    f = defaultdict(bytearray)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or line.startswith("ts_ms,"):
                continue
            p = line.rstrip("\n").split(",")
            if len(p) < 9 or p[2] != "tcp":
                continue
            try:
                pay = strip_ip(bytes.fromhex(p[8]))
            except ValueError:
                continue
            if pay:
                f[(p[3], p[4], p[5], p[6])] += pay
    return f


def main():
    for root, _d, files in os.walk(CAP):
        for fn in sorted(files):
            if not fn.endswith("passthrough_capture.csv"):
                continue
            path = os.path.join(root, fn)
            print("=" * 74)
            print(os.path.relpath(path, CAP))
            print("=" * 74)
            for (src, sport, dst, dport), buf in flows(path).items():
                b = bytes(buf)
                for m in REQ_LINE.finditer(b):
                    if b"GateInfo.php" not in b[m.start():m.start() + 60]:
                        continue
                    print("--- REQ  %s:%s -> %s:%s ---" % (src, sport, dst, dport))
                    seg = b[m.start():]
                    if b"\r\n\r\n" in seg:
                        head, body = seg.split(b"\r\n\r\n", 1)
                    else:
                        head, body = seg, b""
                    print(head.decode("latin1", "replace"))
                    print("BODY_HEX: %s" % body[:220].hex())
                    print("BODY_TXT: %s" % body[:220].decode("latin1", "replace"))
            # responses: look for STATUS: in server->phone direction
            for (src, sport, dst, dport), buf in flows(path).items():
                b = bytes(buf)
                if b"STATUS:" not in b:
                    continue
                i = b.find(b"STATUS:")
                if src.startswith("10."):
                    continue
                print("--- RESP %s:%s -> %s:%s ---" % (src, sport, dst, dport))
                print(b[max(0, i - 200):i + 300].decode("latin1", "replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
