#!/usr/bin/env python3
"""Find the GateInfo.php header set NTL accepts.

The captured request carries only Host/Accept/Content-Length/Content-Type --
no User-Agent, no Connection.  probe_ntl.py added both and got NTL's own
'STATUS: 400'.  This sweeps header variants against the real endpoint and
reports the response BODY for each, so the accepted set is measured rather
than guessed.  Read-only apart from the HTTP POSTs the game itself makes.
"""
import binascii
import json
import socket
import sys
import time

HOST, PORT = "35.174.175.11", 80
PATH = "/ntl/api/GateInfo.php"

# byte-for-byte the JSON the real client hexes into req=
JSON_EXACT = ('{"titleCode":"PES2022","locale":"US","version":"6.0.1",'
              '"extr":"","apiLevel":"4"}')
BODY = ("req=" + binascii.hexlify(JSON_EXACT.encode()).decode()).encode()

# sanity: our json.dumps must equal the captured string exactly
assert JSON_EXACT == json.dumps(
    {"titleCode": "PES2022", "locale": "US", "version": "6.0.1",
     "extr": "", "apiLevel": "4"}, separators=(",", ":")), "json mismatch"

VARIANTS = [
    ("captured (4 hdrs, no UA, no conn)", [
        ("Host", "ntl.service.konami.net"),
        ("Accept", "*/*"),
        ("Content-Length", str(len(BODY))),
        ("Content-Type", "application/x-www-form-urlencoded"),
    ]),
    ("captured + Connection: close", [
        ("Host", "ntl.service.konami.net"),
        ("Accept", "*/*"),
        ("Content-Length", str(len(BODY))),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Connection", "close"),
    ]),
    ("captured + okhttp UA", [
        ("Host", "ntl.service.konami.net"),
        ("User-Agent", "okhttp/4.12.0"),
        ("Accept", "*/*"),
        ("Content-Length", str(len(BODY))),
        ("Content-Type", "application/x-www-form-urlencoded"),
    ]),
    ("okhttp UA + Connection close", [
        ("Host", "ntl.service.konami.net"),
        ("User-Agent", "okhttp/4.12.0"),
        ("Accept", "*/*"),
        ("Content-Length", str(len(BODY))),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Connection", "close"),
    ]),
]


def post(hdrs, timeout=10):
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        s.settimeout(timeout)
        lines = ["POST %s HTTP/1.1" % PATH]
        for k, v in hdrs:
            lines.append("%s: %s" % (k, v))
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + BODY
        s.sendall(raw)
        chunks = []
        while True:
            d = s.recv(4096)
            if not d:
                break
            chunks.append(d)
        return b"".join(chunks)
    finally:
        s.close()


def main():
    print("BODY (%d bytes): %s" % (len(BODY), BODY.decode()))
    print("JSON: %s" % JSON_EXACT)
    print("-" * 74)
    for name, hdrs in VARIANTS:
        for attempt in range(2):
            t0 = time.time()
            try:
                r = post(hdrs)
                head = r.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
                body = r[len(head) + 4:].decode("latin1", "replace")
                status = head.splitlines()[0] if head else "?"
                print("[%5.2fs] %-38s -> %s | BODY=%r" % (
                    time.time() - t0, name, status, body[:120]))
                break
            except Exception as e:                                  # noqa: BLE001
                print("[%5.2fs] %-38s -> %s: %s" % (
                    time.time() - t0, name, type(e).__name__, e))
                time.sleep(1.0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
