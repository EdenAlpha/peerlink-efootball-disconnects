#!/usr/bin/env python3
"""probe_dtlsvip.py -- confirm the real client's 30xxx flows are DTLS, then
probe those EXACT endpoints live.

passthrough_capture.csv (2026-09-26, z1-tiamant-client) is the ground truth
for where a real phone's Konami-side DTLS actually goes.  The top UDP flows
by packet count were:

    10.0.0.2:37135 <-> 34.156.177.234:30236   (594/186 pkts)
    10.0.0.2:46234 <-> 34.156.177.234:30116   (218/225)
    10.0.0.2:54763 <-> 104.199.46.171:30222   (271/278)
    10.0.0.2:36078 <-> 34.22.210.195:30650    (184/190)
    10.0.0.2:52134 <-> 34.38.190.21:30905     ( 54/ 60)

An earlier probe of the *named* 30xxx fleet went 0/9, but these five were
never tried -- they are the ones a real match actually used.

  python probe_dtlsvip.py           confirm DTLS in capture + live probe
  python probe_dtlsvip.py --capture only
"""
import csv
import collections
import socket
import struct
import sys
import time

CAP = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
       r"efootball-disconnects\captures\match-2026-09-26"
       + "\\z1-tiamant-client\\passthrough_capture.csv")

# The five endpoints seen above, filled from the capture scan at runtime.
TARGETS = [
    ("34.156.177.234", 30236),
    ("34.156.177.234", 30116),
    ("104.199.46.171", 30222),
    ("34.22.210.195", 30650),
    ("34.38.190.21", 30905),
    ("34.156.177.234", 30000),
]


def udp_payload(raw_hex):
    """payload_hex is a complete IP packet; strip IP header, then UDP."""
    try:
        b = bytes.fromhex(raw_hex)
    except ValueError:
        return None, None, None
    if not b:
        return None, None, None
    ver = b[0] >> 4
    if ver == 4:
        ihl = (b[0] & 0x0F) * 4
        if len(b) < ihl + 8 or b[9] != 17:
            return None, None, None
        return b[ihl + 8:], b[:4], b[ihl + 4:ihl + 8]
    if ver == 6:
        if len(b) < 48 or b[6] != 17:
            return None, None, None
        return b[48:], b[8:24], b[40:44]
    return None, None, None


def scan_capture():
    print("=== capture scan: content of the 30xxx flows ===")
    seen = collections.OrderedDict()
    with open(CAP, newline="", encoding="utf-8", errors="replace") as f:
        rows = csv.DictReader(ln for ln in f if not ln.startswith("#"))
        for row in rows:
            if row.get("proto", "").lower() != "udp":
                continue
            dst, dport = row.get("dst"), row.get("dport")
            if not dst or not dport or not (29000 <= int(dport) <= 31000):
                continue
            pl = (row.get("payload_hex") or "").strip()
            body, _, _ = udp_payload(pl)
            if not body or len(body) < 13:
                continue
            key = (row["src"], row["sport"], dst, dport)
            if key in seen:
                continue
            ct = body[0]
            kind = {0x16: "DTLS-hs", 0x17: "DTLS-appdata", 0x15: "DTLS-alert",
                    0x14: "DTLS-ccs"}.get(ct, "other(0x%02x)" % ct)
            ver = struct.unpack("!H", body[1:3])[0] if len(body) >= 3 else 0
            hs = body[13] if (ct == 0x16 and len(body) > 13) else -1
            seen[key] = (kind, ver, hs, len(body), row["dir"])
    for k, v in seen.items():
        print("  %s:%s -> %s:%s  %-13s ver=%s hs=%d len=%d  dir=%s"
              % (k[0], k[1], k[2], k[3], v[0],
                 ("0x%04x" % v[1]) if v[1] else "-", v[2], v[3], v[4]))
    return list({(k[2], int(k[3])) for k in seen})


def clienthello(version=0xFEFD):
    rnd = bytes(range(0x20, 0x60))
    suites = struct.pack("!HHHHHH", 0xC02B, 0xC02F, 0xC02C,
                         0xC030, 0xC013, 0xC014)
    curves = struct.pack("!HH", 10, 4) + struct.pack("!HH", 0x0017, 0x0018)
    ptfmt = struct.pack("!HH", 11, 2) + b"\x01\x00"
    sigs = struct.pack("!HH", 13, 4) + struct.pack("!HH", 0x0403, 0x0503)
    ext = curves + ptfmt + sigs
    body = (struct.pack("!H", version) + rnd + b"\x00" + b"\x00"
            + struct.pack("!H", len(suites)) + suites
            + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    hs = (b"\x01" + len(body).to_bytes(3, "big")
          + struct.pack("!H", 0) + b"\x00" * 6
          + b"\x00\x00\x00" + len(body).to_bytes(3, "big") + body)
    return (b"\x16" + struct.pack("!H", version) + b"\x00\x00" + b"\x00" * 6
            + struct.pack("!H", len(hs)) + hs)


def probe(ip, port, timeout=4.0):
    """Send a DTLS ClientHello; a real server answers with hello_verify
    (hs_type 3) or a ServerHello (2) / Alert (21)."""
    out = []
    for label, ver in (("1.2", 0xFEFD), ("1.0", 0xFEFF)):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(clienthello(ver), (ip, port))
            t0 = time.time()
            d, frm = s.recvfrom(4096)
        except socket.timeout:
            out.append("%s:timeout" % label)
            continue
        except OSError as e:
            out.append("%s:err %s" % (label, e))
            continue
        finally:
            s.close()
        ms = int((time.time() - t0) * 1000)
        if d[:1] == b"\x16" and len(d) > 13:
            hst = {0: "hello_request", 1: "client_hello", 2: "server_hello",
                   3: "hello_verify", 11: "certificate", 12: "skeyx",
                   14: "server_hello_done"}.get(d[13], "hs%d" % d[13])
            out.append("%s:ANSWERED DTLS hs=%s len=%d %dms"
                       % (label, hst, len(d), ms))
        else:
            out.append("%s:ANSWERED len=%d head=%s %dms"
                       % (label, len(d), d[:8].hex(), ms))
    return " | ".join(out)


def main() -> int:
    caps = scan_capture()
    # keep capture-derived endpoints first, then the fixed list
    ordered, seen = [], set()
    for ip, port in caps + TARGETS:
        if (ip, port) not in seen:
            seen.add((ip, port))
            ordered.append((ip, port))
    print("\n=== live DTLS probe ===")
    for ip, port in ordered:
        print("  %-16s %-6s  %s" % (ip, port, probe(ip, port)))
    return 0


if __name__ == "__main__":
    main()
