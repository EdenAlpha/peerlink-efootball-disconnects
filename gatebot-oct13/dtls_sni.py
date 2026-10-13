#!/usr/bin/env python3
"""dtls_sni.py -- extract SNI hostname + record structure from the PeerLink DTLS
ClientHellos sent to Konami's Google-Cloud servers (match-2026-09-26 capture).

The DTLS app data is encrypted, but the ClientHello handshake is plaintext and
carries the SNI extension naming the Konami service.  This identifies WHAT the
PeerLink SDK connects to during the ~1k-packet establishment -- the server-
visible part chain3 never replicates.

Read-only.  python dtls_sni.py
"""
import os
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")
Z = ("z1-tiamant-client", "z2-elijah-hotspot-owner")


def is_local(ip):
    return ip.startswith(("10.", "192.168.", "172."))


def parse_dtls_records(udp):
    recs = []
    i = 0
    while i + 13 <= len(udp):
        ct = udp[i]
        if ct not in (20, 21, 22, 23):
            break
        ver = int.from_bytes(udp[i + 1:i + 3], "big")
        ln = int.from_bytes(udp[i + 11:i + 13], "big")
        if i + 13 + ln > len(udp):
            break
        body = udp[i + 13:i + 13 + ln]
        recs.append((ct, ver, ln, body))
        i += 13 + ln
    return recs


def sni_from_clienthello(hs_body):
    """hs_body = handshake message body after the 12-byte hs header."""
    # client_hello: version(2) random(32) session_id(1+sid) cookie(1+cookie)
    #               cipher_suites(2+n) comp(1+n) extensions(2+n)
    try:
        i = 0
        i += 2 + 32                       # version + random
        sid_len = hs_body[i]; i += 1 + sid_len
        cookie_len = hs_body[i]; i += 1 + cookie_len
        cs_len = int.from_bytes(hs_body[i:i + 2], "big"); i += 2 + cs_len
        comp_len = hs_body[i]; i += 1 + comp_len
        if i + 2 > len(hs_body):
            return None
        ext_total = int.from_bytes(hs_body[i:i + 2], "big"); i += 2
        end = i + ext_total
        while i + 4 <= end and i + 4 <= len(hs_body):
            et = int.from_bytes(hs_body[i:i + 2], "big")
            el = int.from_bytes(hs_body[i + 2:i + 4], "big")
            ed = hs_body[i + 4:i + 4 + el]
            if et == 0x0000 and len(ed) >= 5:      # SNI
                # list_len(2) type(1) len(2) name
                nl = int.from_bytes(ed[3:5], "big")
                return ed[5:5 + nl].decode("utf-8", "replace")
            i += 4 + el
    except (IndexError, ValueError):
        return None
    return None


for z in Z:
    print("=" * 78)
    print(z)
    print("=" * 78)
    pp = os.path.join(CAP, z, "passthrough_capture.csv")
    seen = set()
    with open(pp, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or line.startswith("ts_ms,") \
                    or not line.strip():
                continue
            p = line.rstrip("\n").split(",")
            if len(p) < 9 or p[2] != "udp":
                continue
            dst, dp, hx = p[5], p[6], p[8]
            if is_local(dst):
                continue
            try:
                b = bytes.fromhex(hx)
            except ValueError:
                continue
            ihl = (b[0] & 0xF) * 4
            udp = b[ihl + 8:]
            for (ct, ver, ln, body) in parse_dtls_records(udp):
                if ct == 22 and body and body[0] == 1:   # handshake / ClientHello
                    hs_body = body[12:]                  # skip hs header (12B)
                    sni = sni_from_clienthello(hs_body)
                    key = (dst, dp, sni)
                    if key in seen:
                        continue
                    seen.add(key)
                    print("  %s:%s  DTLS ver=0x%04x  SNI=%s" %
                          (dst, dp, ver, sni))
    print()
