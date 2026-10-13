#!/usr/bin/env python3
"""dtls_ident.py -- confirm the Konami DTLS servers + dump a raw ClientHello.

Reverse-DNS the Google-Cloud IPs the PeerLink SDK opens DTLS to, and dump the
first ClientHello handshake body (plaintext) to look for a service name / cookie
/ cipher-suite fingerprint identifying the Konami session service.

Read-only.  python dtls_ident.py
"""
import os
import socket
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")
Z = ("z1-tiamant-client", "z2-elijah-hotspot-owner")


def is_local(ip):
    return ip.startswith(("10.", "192.168.", "172."))


def strings(b, n=4):
    out, cur = [], b""
    for x in b:
        if 32 <= x < 127:
            cur += bytes([x])
        else:
            if len(cur) >= n:
                out.append(cur.decode())
            cur = b""
    if len(cur) >= n:
        out.append(cur.decode())
    return out


# ---- pass 1: collect the DTLS server IPs + first ClientHello body per endpoint
eps = {}          # (ip, port) -> (first_clienthello_body, strings)
for z in Z:
    pp = os.path.join(CAP, z, "passthrough_capture.csv")
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
            # DTLS handshake record?
            if len(udp) > 13 and udp[0] == 22 and (dst, dp) not in eps:
                ln = int.from_bytes(udp[11:13], "big")
                body = udp[13:13 + ln]
                # handshake type 1 = ClientHello
                if body and body[0] == 1:
                    eps[(dst, dp)] = (body, strings(body))

print("=" * 78)
print("DTLS server endpoints + reverse-DNS")
print("=" * 78)
seen_ip = {}
for (ip, port) in sorted(eps):
    if ip not in seen_ip:
        try:
            host = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            host = "?"
        seen_ip[ip] = host
    print("  %s:%-6s  <- %s" % (ip, port, seen_ip[ip]))

print()
print("=" * 78)
print("raw first ClientHello (one per server IP)")
print("=" * 78)
done = set()
for (ip, port), (body, st) in sorted(eps.items()):
    if ip in done:
        continue
    done.add(ip)
    print("  %s:%s" % (ip, port))
    print("     len=%d  strings=%s" % (len(body), st[:12]))
    print("     hex[:96]=%s" % body[:96].hex())
    print()
