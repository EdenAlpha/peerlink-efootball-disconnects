#!/usr/bin/env python3
"""t7_raw.py -- send one RP_ request to Konami STUN, dump any reply raw."""
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p2p_stun import REQ, attr, build, p2p_header  # noqa: E402

STUN_HOST = os.environ.get("STUN_HOST", "pesam.stun.service.konami.net")
STUN_PORT = int(os.environ.get("STUN_PORT", "3478"))
UID = "2032791990"

infos = socket.getaddrinfo(STUN_HOST, STUN_PORT, socket.AF_INET,
                           socket.SOCK_DGRAM)
dest = infos[0][4]
print("dest =", dest)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 44000))
tid = os.urandom(12)
msg = build(REQ, tid, attr(0x9090, p2p_header(UID)))
sock.sendto(msg, dest)
print("sent %d bytes: %s" % (len(msg), msg.hex()))

sock.settimeout(6.0)
try:
    buf, src = sock.recvfrom(4096)
    print("REPLY from %s: %d bytes %s" % (src, len(buf), buf.hex()))
except socket.timeout:
    print("no reply in 6s")

# also try a plain STUN binding request (method 0x001) in case RP_ is ignored
from p2p_stun import MAGIC  # noqa: E402
bind = b"\x00\x01\x00\x00" + MAGIC + os.urandom(12)
sock.sendto(bind, dest)
print("sent plain binding")
try:
    buf, src = sock.recvfrom(4096)
    print("REPLY from %s: %d bytes %s" % (src, len(buf), buf.hex()))
except socket.timeout:
    print("no reply in 6s")
