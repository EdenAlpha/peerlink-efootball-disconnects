#!/usr/bin/env python3
"""Decode the passthrough capture's hex IP payloads and find NTL HTTP traffic.

NTL is plain HTTP (POST http://ntl.service.konami.net/ntl/api/GateInfo.php),
so the request lines and bodies are visible in the capture even though every
row is a hex-encoded full IP packet.  This reconstructs the TCP payloads per
(src,sport)->(dst,dport) flow and prints every HTTP request line plus the
first bytes of its body, restricted to Konami NTL hosts.

Read-only.  Never sends anything.
"""
import os
import re
import sys
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")

KONAMI = (b"konami", b"GateInfo", b"ReportLog", b"ntl.service",
          b"pes22-game", b"CmdGet", b"CmdSet", b"CmdCheck", b"CmdStart")

REQ_LINE = re.compile(rb"^(GET|POST|PUT) ([^ \r\n]+) HTTP/1\.[01]")


def strip_ip_packet(raw: bytes):
    """raw = complete IPv4 packet.  -> TCP payload (bytes) or b''."""
    if len(raw) < 20:
        return b""
    vihl = raw[0]
    if (vihl >> 4) != 4:
        return b""
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl:
        return b""
    proto = raw[9]
    if proto != 6:                       # TCP only
        return b""
    if len(raw) < ihl + 20:
        return b""
    tcp = raw[ihl:]
    off = ((tcp[12] >> 4) & 0x0F) * 4
    if off < 20 or len(tcp) < off:
        return b""
    return tcp[off:]


def scan(path, want_ts=None):
    flows = defaultdict(bytearray)
    meta = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or line.startswith("ts_ms,"):
                continue
            parts = line.rstrip("\n").split(",")
            if len(parts) < 9:
                continue
            ts, d, proto, src, sport, dst, dport = parts[:7]
            hexs = parts[8]
            if proto != "tcp":
                continue
            try:
                raw = bytes.fromhex(hexs)
            except ValueError:
                continue
            pay = strip_ip_packet(raw)
            if not pay:
                continue
            key = (src, sport, dst, dport)
            flows[key] += pay
            meta.setdefault(key, (ts, d))
    return flows, meta


def report(path):
    print("=== %s ===" % os.path.relpath(path, CAP))
    flows, meta = scan(path)
    seen_hosts = defaultdict(int)
    n_http = 0
    for key, buf in flows.items():
        src, sport, dst, dport = key
        ts, d = meta[key]
        for m in REQ_LINE.finditer(bytes(buf)):
            n_http += 1
            start = m.start()
            seg = bytes(buf)[start:start + 400]
            head = seg.split(b"\r\n\r\n", 1)
            hdrs = head[0].decode("latin1", "replace")
            body = head[1][:200].decode("latin1", "replace") if len(head) > 1 else ""
            host = ""
            for h in hdrs.split("\r\n"):
                if h.lower().startswith("host:"):
                    host = h.split(":", 1)[1].strip()
            seen_hosts[host] += 1
            # only print Konami/NTL traffic, or anything with a Cmd*.php path
            if "konami" in host.lower() or ".php" in m.group(2).decode("latin1", "replace"):
                print("  [%s %s] %s:%s -> %s:%s" % (ts, d, src, sport, dst, dport))
                print("    %s" % m.group(0).decode("latin1", "replace"))
                for h in hdrs.split("\r\n")[1:]:
                    print("      %s" % h)
                if body:
                    print("      BODY: %s" % body.replace("\r", " ").replace("\n", " ")[:200])
    print("  total HTTP requests: %d" % n_http)
    print("  hosts: %s" % dict(sorted(seen_hosts.items(), key=lambda kv: -kv[1])[:20]))


def main():
    for root, _d, files in os.walk(CAP):
        for fn in sorted(files):
            if fn.endswith("passthrough_capture.csv"):
                report(os.path.join(root, fn))
    return 0


if __name__ == "__main__":
    sys.exit(main())
