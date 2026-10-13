#!/usr/bin/env python3
"""relay_probe.py -- probe the Konami relay endpoints from this VM.

The session's gamerelay spec gave three candidates + a token.  This
learns: does egress reach them, what do they answer (UDP hello /
TCP+TLS on 443), and does anything look STUN-shaped.

  python relay_probe.py
"""
import socket
import struct
import time

UDP = [("34.175.250.31", 5735), ("34.175.83.169", 5736)]
TCP = [("34.175.83.169", 443)]

MAGIC = 0x2112A442


def stun_req():
    txid = b"\x01" * 12
    return struct.pack(">HHI", 0x0001, 0, MAGIC) + txid


def main() -> int:
    for ip, port in UDP:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        for name, payload in (("stun", stun_req()),
                              ("zero", b"\x00" * 16),
                              ("text", b"HELLO\n")):
            try:
                s.sendto(payload, (ip, port))
                t0 = time.time()
                data, addr = s.recvfrom(2048)
                print("UDP %s:%d [%s] -> %d bytes from %s:%d after %.2fs: %s"
                      % (ip, port, name, len(data), addr[0], addr[1],
                         time.time() - t0, data[:48].hex()))
            except socket.timeout:
                print("UDP %s:%d [%s] -> timeout (no answer)"
                      % (ip, port, name))
            except OSError as e:
                print("UDP %s:%d [%s] -> %s" % (ip, port, name, e))
        s.close()

    for ip, port in TCP:
        try:
            s = socket.create_connection((ip, port), timeout=4)
            s.settimeout(3)
            print("TCP %s:%d -> connected" % (ip, port))
            try:
                s.sendall(b"\x16\x03\x01\x00\x00")     # TLS clienthello-ish
                data = s.recv(64)
                print("  TLS-ish reply: %s" % data[:32].hex())
            except OSError as e:
                print("  send/recv: %s" % e)
            s.close()
        except OSError as e:
            print("TCP %s:%d -> %s" % (ip, port, e))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
