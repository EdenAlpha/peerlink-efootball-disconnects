#!/usr/bin/env python3
"""Test NTL reachability the way the real game does it.

The capture shows the real client POSTing GateInfo.php to 35.174.175.11:80
(ntl.service.konami.net) over plain HTTP with User-Agent okhttp/4.12.0.
chain3's ntl_gateinfo() has been timing out -- if NTL session state is what
the gate cross-references, a dead NTL handshake would read as "session never
existed" -> DISCONN_HB.

Sends the exact captured bytes.  Retry/backoff per the pending next-move.
"""
import binascii
import json
import socket
import sys
import time

HOSTS = [("35.174.175.11", 80), ("ntl.service.konami.net", 80)]
PATH = "/ntl/api/GateInfo.php"
BODY_JSON = (json.dumps({"titleCode": "PES2022", "locale": "US",
                         "version": "6.0.1", "extr": "", "apiLevel": "4"},
                        separators=(",", ":")))
BODY = ("req=" + binascii.hexlify(BODY_JSON.encode()).decode()).encode()


def attempt(host, port, timeout):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.settimeout(timeout)
        req = ("POST %s HTTP/1.1\r\n"
               "Host: ntl.service.konami.net\r\n"
               "Accept: */*\r\n"
               "Content-Length: %d\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n"
               "User-Agent: okhttp/4.12.0\r\n"
               "Connection: close\r\n\r\n" % (PATH, len(BODY))).encode()
        s.sendall(req + BODY)
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
    for host, port in HOSTS:
        for i in range(3):
            t0 = time.time()
            try:
                r = attempt(host, port, 8)
                head = r.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
                body = r[len(head) + 4:len(head) + 4 + 400].decode(
                    "latin1", "replace")
                print("[%.2fs] %s:%d try%d -> %d bytes" % (
                    time.time() - t0, host, port, i, len(r)))
                for ln in head.splitlines()[:8]:
                    print("    %s" % ln)
                print("    BODY: %s" % body.replace("\r", " ").replace("\n", " | ")[:400])
                return 0
            except Exception as e:                                  # noqa: BLE001
                print("[%.2fs] %s:%d try%d -> %s: %s" % (
                    time.time() - t0, host, port, i, type(e).__name__, e))
                time.sleep(1.5 * (i + 1))
    return 1


if __name__ == "__main__":
    sys.exit(main())
