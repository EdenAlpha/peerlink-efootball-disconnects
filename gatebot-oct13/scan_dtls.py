#!/usr/bin/env python3
"""Recover the real game's DTLS handshake against the Konami relay.

NEXT-MOVE #4 needs a TURN-over-DTLS Allocate against a measured relay.  The
photocopier rule says copy the real bytes, so this extracts every DTLS record
from the captures and prints the handshake in order: ClientHello ->
HelloVerifyRequest -> cookie ClientHello -> ServerHello+cert -> ...

Read-only.  Never sends anything.
"""
import os
import sys
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")

CONTENT_TYPES = {20: "CCS", 21: "alert", 22: "handshake", 23: "appdata"}
HS_TYPES = {0: "hello_request", 1: "client_hello", 2: "server_hello",
            3: "hello_verify_request", 11: "certificate",
            12: "server_key_exchange", 13: "certificate_request",
            14: "server_hello_done", 15: "certificate_verify",
            16: "client_key_exchange", 20: "finished"}


def strip_udp(raw):
    if len(raw) < 28 or (raw[0] >> 4) != 4:
        return None
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or raw[9] != 17 or len(raw) < ihl + 8:
        return None
    udp = raw[ihl:]
    sport = int.from_bytes(udp[0:2], "big")
    dport = int.from_bytes(udp[2:4], "big")
    return sport, dport, udp[8:]


def parse_dtls(buf):
    """Yield (offset, ct, version, epoch, seq, len, hs_type, payload)."""
    out = []
    i = 0
    while i + 13 <= len(buf):
        ct = buf[i]
        if ct not in CONTENT_TYPES:
            break
        ver = int.from_bytes(buf[i + 1:i + 3], "big")
        epoch = int.from_bytes(buf[i + 3:i + 5], "big")
        seq = int.from_bytes(buf[i + 5:i + 11], "big")
        ln = int.from_bytes(buf[i + 11:i + 13], "big")
        if i + 13 + ln > len(buf):
            break
        body = buf[i + 13:i + 13 + ln]
        hs = None
        if ct == 22 and len(body) >= 4:
            hs = body[0]
        out.append((i, ct, ver, epoch, seq, ln, hs, body))
        i += 13 + ln
    return out


def main():
    for root, _d, files in os.walk(CAP):
        for fn in sorted(files):
            if not fn.endswith("passthrough_capture.csv"):
                continue
            path = os.path.join(root, fn)
            print("=" * 74)
            print(os.path.relpath(path, CAP))
            print("=" * 74)
            flows = defaultdict(bytearray)
            order = []
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("#") or line.startswith("ts_ms,"):
                        continue
                    p = line.rstrip("\n").split(",")
                    if len(p) < 9 or p[2] != "udp":
                        continue
                    try:
                        r = strip_udp(bytes.fromhex(p[8]))
                    except ValueError:
                        continue
                    if not r:
                        continue
                    sport, dport, pay = r
                    if not pay or pay[0] not in CONTENT_TYPES:
                        continue
                    key = (p[3], sport, p[5], dport)
                    if key not in flows:
                        order.append(key)
                    flows[key] += pay
            for key in order:
                buf = bytes(flows[key])
                recs = parse_dtls(buf)
                if not recs:
                    continue
                src, sport, dst, dport = key
                print("--- flow %s:%d -> %s:%d  (%d DTLS records) ---"
                      % (src, sport, dst, dport, len(recs)))
                for (off, ct, ver, epoch, seq, ln, hs, body) in recs:
                    label = CONTENT_TYPES[ct]
                    extra = ""
                    if hs is not None:
                        extra = HS_TYPES.get(hs, "hs=%d" % hs)
                        if hs == 1 and len(body) >= 6:
                            cid = int.from_bytes(body[4:6], "big")
                            extra += " client_id=0x%04x body=%dB" % (cid, ln)
                        elif hs == 2:
                            extra += " body=%dB" % ln
                        elif hs == 3:
                            extra += " verify_len=%dB" % (len(body) - 4)
                    print("   +%5d %-9s ver=0x%04x ep=%d seq=%d len=%3d %s"
                          % (off, label, ver, epoch, seq, ln, extra))
                print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
