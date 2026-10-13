#!/usr/bin/env python3
"""t7_probe.py -- try RP_ keepalive variants against both Konami STUN IPs."""
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p2p_stun import REQ, RES, attr, build, p2p_header, MAGIC  # noqa: E402

UID = "2032791990"
IPS = ["35.76.243.83", "54.64.79.140"]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 44000))
sock.settimeout(2.0)

BIND = 0x0001          # T7 = plain BINDING_REQUEST carrying 0x9090/0x9091


def breq(attrs=b""):
    hdr = struct.pack(">HH", BIND, len(attrs)) + MAGIC + os.urandom(12)
    return hdr + attrs


variants = [
    ("bind+0x9090", breq(attr(0x9090, p2p_header(UID)))),
    ("bind+0x9091", breq(attr(0x9091, p2p_header(UID)))),
    ("bind+both", breq(attr(0x9090, p2p_header(UID)) +
                       attr(0x9091, p2p_header(UID)))),
    ("bind+0x9090空", breq(attr(0x9090, b""))),
    ("req+0x9090", build(REQ, os.urandom(12), attr(0x9090, p2p_header(UID)))),
    ("req bare", b"\x00\x01\x00\x00" + MAGIC + os.urandom(12)),
]

for ip in IPS:
    dest = (ip, 3478)
    for name, msg in variants:
        sock.sendto(msg, dest)
        t0 = time.monotonic()
        try:
            buf, src = sock.recvfrom(4096)
            print("%s %-14s -> REPLY %d bytes from %s in %.2fs: %s..."
                  % (ip, name, len(buf), src, time.monotonic() - t0,
                     buf[:16].hex()))
        except socket.timeout:
            print("%s %-14s -> no reply" % (ip, name))
