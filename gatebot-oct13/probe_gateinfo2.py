#!/usr/bin/env python3
"""Probe GateInfo with the CORRECTED key (`extra`, not `extr`).

Byte-diff of the capture showed the real client's JSON key is `extra`; chain3
and probe_ntl both sent `extr`, and NTL answered STATUS:400 for every header
variant.  This sends the corrected body and reports the reply.
"""
import binascii
import socket
import sys
import time

HOST, PORT = "35.174.175.11", 80
PATH = "/ntl/api/GateInfo.php"

# exactly the 81-byte captured JSON, key = extra
JSON_EXACT = ('{"titleCode":"PES2022","locale":"US","version":"6.0.1",'
              '"extra":"","apiLevel":"4"}')
BODY = ("req=" + binascii.hexlify(JSON_EXACT.encode()).decode()).encode()

HEADERS = [
    ("Host", "ntl.service.konami.net"),
    ("Accept", "*/*"),
    ("Content-Length", str(len(BODY))),
    ("Content-Type", "application/x-www-form-urlencoded"),
]


def post(timeout=12):
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        s.settimeout(timeout)
        head = "POST %s HTTP/1.1\r\n" % PATH
        head += "".join("%s: %s\r\n" % kv for kv in HEADERS)
        s.sendall(head.encode() + b"\r\n" + BODY)
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
    print("JSON (%d bytes): %s" % (len(JSON_EXACT), JSON_EXACT))
    print("BODY (%d bytes, expect 166): %s" % (len(BODY), BODY.decode()))
    print("-" * 74)
    for i in range(4):
        t0 = time.time()
        try:
            r = post()
            head = r.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
            body = r[len(head) + 4:].decode("latin1", "replace")
            print("[%.2fs] %s" % (time.time() - t0, head.splitlines()[0]))
            for ln in body.splitlines():
                print("   %s" % ln)
            return 0 if "STATUS: 200" in body else 1
        except Exception as e:                                      # noqa: BLE001
            print("[%.2fs] try%d -> %s: %s" % (time.time() - t0, i,
                                               type(e).__name__, e))
            time.sleep(1.5 * (i + 1))
    return 1


if __name__ == "__main__":
    sys.exit(main())
