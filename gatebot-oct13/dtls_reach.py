#!/usr/bin/env python3
"""dtls_reach.py -- can this VM reach the Konami DTLS relay fleet at all?

Sends ONE DTLS ClientHello (the exact template from the capture) to each known
30xxx endpoint and waits for a HelloVerifyRequest / ServerHello.  Read-mostly:
it only sends a ClientHello, the same first packet the real game sends.  Prints
reachability so we know the relay path is open before building a full client.

  python dtls_reach.py
"""
import os
import socket
import time

# exact ClientHello (handshake body) captured from the real client, first flight
# ver=0xfefd (DTLS 1.2).  Rebuilt from dtls_ident.py output for one endpoint.
CH_BODY = bytes.fromhex(
    "010000aa00000000000000aafefd2ce000aae7c834630cfa8c0d48d28b2e1a4a5560"
    "a8b8750fbb4255563fd68db200000032c02cc030009fc02bc02f009ec024c028006b"
    "c023c0270067c00ac0140039c009c0130033009d009c003d003c0035")

ENDPOINTS = [
    ("34.156.177.234", 30116),
    ("34.156.177.234", 30236),
    ("34.156.177.234", 31840),
    ("34.22.210.195", 30650),
    ("34.22.210.195", 30970),
    ("34.38.190.21", 30905),
    ("35.233.88.176", 32741),
    ("35.240.102.10", 31406),
    ("104.199.46.171", 30222),
]

HS_TYPES = {0: "hello_request", 1: "client_hello", 2: "server_hello",
            3: "hello_verify_request", 11: "certificate",
            12: "server_key_exchange", 14: "server_hello_done",
            20: "finished"}


def dtls_record(hs_type, body, epoch=0, seq=0, version=0xfefd):
    """wrap a handshake body in a DTLS record."""
    hs = bytes([hs_type]) + len(body).to_bytes(3, "big") \
        + (0).to_bytes(2, "big") + (0).to_bytes(3, "big") + body
    return (bytes([22]) + version.to_bytes(2, "big")
            + epoch.to_bytes(2, "big") + seq.to_bytes(6, "big")
            + len(hs).to_bytes(2, "big") + hs)


def label(payload):
    """describe a DTLS response payload."""
    out = []
    i = 0
    while i + 13 <= len(payload):
        ct = payload[i]
        if ct not in (20, 21, 22, 23):
            break
        ver = int.from_bytes(payload[i + 1:i + 3], "big")
        epoch = int.from_bytes(payload[i + 3:i + 5], "big")
        ln = int.from_bytes(payload[i + 11:i + 13], "big")
        body = payload[i + 13:i + 13 + ln]
        name = {20: "CCS", 21: "alert", 22: "handshake", 23: "appdata"}.get(ct, str(ct))
        extra = ""
        if ct == 22 and len(body) >= 4:
            ht = body[0]
            extra = HS_TYPES.get(ht, "hs=%d" % ht)
            if ht == 3:  # hello_verify_request -> cookie
                ck = body[6:]
                extra += " cookie=%dB %s" % (len(ck), ck.hex())
        out.append("%s ver=0x%04x ep=%d len=%d %s" % (name, ver, epoch, ln, extra))
        i += 13 + ln
    return "; ".join(out) or "raw(%dB)" % len(payload)


def probe(ip, port, timeout=4.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rec = dtls_record(1, CH_BODY)
    try:
        sock.sendto(rec, (ip, port))
        t0 = time.time()
        data, src = sock.recvfrom(2048)
        return True, "%.2fs %s" % (time.time() - t0, label(data))
    except socket.timeout:
        return False, "timeout %.1fs" % timeout
    except OSError as e:
        return False, "err %s" % e
    finally:
        sock.close()


if __name__ == "__main__":
    print("DTLS ClientHello reachability -> Konami relay fleet")
    print("=" * 66)
    ok = 0
    for ip, port in ENDPOINTS:
        good, info = probe(ip, port)
        mark = "OK  " if good else "----"
        if good:
            ok += 1
        print("  %s %s:%-6s  %s" % (mark, ip, port, info))
    print("=" * 66)
    print("reachable: %d/%d" % (ok, len(ENDPOINTS)))
