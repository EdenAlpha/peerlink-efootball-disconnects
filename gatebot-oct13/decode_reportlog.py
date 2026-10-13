#!/usr/bin/env python3
"""Decode the `dat=` field of every ReportLog.php POST in the captures.

The real game logs its P2P session to NTL ReportLog as hex-encoded text
(`## NTLLInfo` + JSON lines).  That log is the game's own record of the
CONNECT phase -- STUN, hole punch, TURN allocation -- which is exactly the
flow our chain never performs.  Reading it beats guessing at the gate.

Read-only.  Never sends anything.
"""
import os
import re
import sys
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")

REQ_LINE = re.compile(rb"^(GET|POST) ([^ \r\n]+) HTTP/1\.[01]")
TYPE_RE = re.compile(rb"[?&]type=([a-z]+)|^type=([a-z]+)")


def strip_ip_packet(raw: bytes) -> bytes:
    if len(raw) < 20 or (raw[0] >> 4) != 4:
        return b""
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl or raw[9] != 6:
        return b""
    tcp = raw[ihl:]
    if len(tcp) < 20:
        return b""
    off = ((tcp[12] >> 4) & 0x0F) * 4
    if off < 20 or len(tcp) < off:
        return b""
    return tcp[off:]


def flows_of(path):
    flows = defaultdict(bytearray)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or line.startswith("ts_ms,"):
                continue
            p = line.rstrip("\n").split(",")
            if len(p) < 9 or p[2] != "tcp":
                continue
            try:
                pay = strip_ip_packet(bytes.fromhex(p[8]))
            except ValueError:
                continue
            if pay:
                flows[(p[3], p[4], p[5], p[6])] += pay
    return flows


def decode_dat(hexstr: str) -> str:
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        return "<not hex>"
    return raw.decode("utf-8", "replace")


def report(path):
    print("=" * 78)
    print(os.path.relpath(path, CAP))
    print("=" * 78)
    for key, buf in flows_of(path).items():
        b = bytes(buf)
        for m in REQ_LINE.finditer(b):
            if b"ReportLog.php" not in b[m.start():m.start() + 60]:
                continue
            start = m.start()
            seg = b[start:]
            head = seg.split(b"\r\n\r\n", 1)
            if len(head) < 2:
                continue
            body = head[1].decode("latin1", "replace")
            # body is urlencoded: type=..&prefix=..&ver=..&dat=<hex>
            tm = re.search(r"[?&]?type=([a-z]+)", body)
            dm = re.search(r"&dat=([0-9a-fA-F]+)", body)
            typ = tm.group(1) if tm else "?"
            print("\n--- type=%s ---" % typ)
            if not dm:
                print("  (no dat field; body[:200]=%s)" % body[:200])
                continue
            txt = decode_dat(dm.group(1))
            # the log is newline separated; print the interesting lines
            for ln in txt.splitlines():
                s = ln.strip()
                if not s:
                    continue
                low = s.lower()
                if (s.startswith("##") or "stun" in low or "turn" in low
                        or "punch" in low or "session" in low
                        or "relay" in low or "alloc" in low
                        or "connect" in low or "error" in low
                        or "warn" in low or "fail" in low
                        or "libver" in low or "state" in low
                        or "peer" in low or "addr" in low):
                    print("   %s" % s[:400])


def main():
    for root, _d, files in os.walk(CAP):
        for fn in sorted(files):
            if fn.endswith("passthrough_capture.csv"):
                report(os.path.join(root, fn))
    return 0


if __name__ == "__main__":
    sys.exit(main())
