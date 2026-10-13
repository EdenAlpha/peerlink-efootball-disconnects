#!/usr/bin/env python3
"""relay_probe3.py -- structured frame iteration on the relay.

Learned so far: server hello = 00 01; client frames are
  [u16be length][payload]   (bad lengths -> FIN)
and a valid-length frame keeps the connection open (no reply yet).

Battery:
  TCP: mirror hello / two-frame name+token / msgpack variants incl.
       empty map to provoke an error listing expected keys.
  UDP: same payloads as datagrams to 5735/5736.
  HTTP: :443 TLS GET/POST without Connection header.

Replies are frame-parsed and msgpack-decoded; long/hex strings redacted.
"""
import json
import socket
import ssl
import struct
import sys
import time

import msgpack

SPEC_FILE = r"C:\Users\Administrator\Documents\Default Project\work\relay_spec.json"
spec = json.load(open(SPEC_FILE, encoding="utf-8"))
NAME, TOKEN, SID = spec["name"], spec["token"], spec["sid"]

TCP = ("34.175.83.169", 5736)
UDPS = [("34.175.250.31", 5735), ("34.175.83.169", 5735),
        ("34.175.83.169", 5736), ("34.175.250.31", 5736)]


def frame(payload):
    return struct.pack(">H", len(payload)) + payload


def redact_str(s):
    if s in (NAME, TOKEN, SID):
        return "<ours len=%d>" % len(s)
    if len(s) > 40:
        return "<str len=%d>" % len(s)
    if all(c in "0123456789abcdef" for c in s) and len(s) >= 24:
        return "<hex len=%d>" % len(s)
    return s


def describe(obj, depth=0):
    if depth > 4:
        return "..."
    if isinstance(obj, dict):
        return "{" + ", ".join("%r: %s" % (k, describe(v, depth + 1))
                               for k, v in obj.items()) + "}"
    if isinstance(obj, (list, tuple)):
        return "[" + ", ".join(describe(v, depth + 1) for v in obj[:8]) + \
            ("..." if len(obj) > 8 else "") + "]"
    if isinstance(obj, str):
        return repr(redact_str(obj))
    if isinstance(obj, bytes):
        return "<bytes len=%d>" % len(obj)
    return repr(obj)


def decode_payload(p):
    if not p:
        return "<empty>"
    try:
        obj = msgpack.unpackb(p, raw=False, strict_map_key=False)
        return describe(obj)
    except Exception:
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in p[:80])
        return "raw: %s |%s|" % (p[:48].hex(), asc)


def read_frames(sock, wait):
    """read everything for `wait` s, split into u16be frames + leftover."""
    sock.settimeout(0.5)
    buf = b""
    t0 = time.time()
    while time.time() - t0 < wait:
        try:
            d = sock.recv(4096)
            if not d:
                return buf, True
            buf += d
        except socket.timeout:
            continue
        except OSError:
            return buf, True
    return buf, False


def report(label, buf, closed):
    if not buf:
        print("    %-26s %s" % (label, "nothing" + (" (FIN)" if closed else "")))
        return
    off = 0
    n = 0
    while off + 2 <= len(buf):
        ln = struct.unpack_from(">H", buf, off)[0]
        if ln > 8192 or off + 2 + ln > len(buf):
            break
        p = buf[off + 2:off + 2 + ln]
        print("    frame[%d] len=%d: %s" % (n, ln, decode_payload(p)))
        off += 2 + ln
        n += 1
    if off < len(buf) or n == 0:
        rest = buf[off:]
        print("    unparsed: %s" % decode_payload(rest))
    if closed:
        print("    (FIN)")


def tcp_case(label, payloads, wait=3.0):
    try:
        s = socket.create_connection(TCP, timeout=6)
        s.settimeout(3)
        hello = b""
        try:
            hello = s.recv(64)
        except socket.timeout:
            pass
        for p in payloads:
            s.sendall(p)
            time.sleep(0.15)
        buf, closed = read_frames(s, wait)
        s.close()
        print("  %-26s hello=%s" % (label, hello.hex() or "-"))
        report("reply", buf, closed)
    except OSError as e:
        print("  %-26s ERROR %s" % (label, e))


def udp_case(tgt, label, payload, wait=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(wait)
    try:
        s.sendto(payload, tgt)
        try:
            data, addr = s.recvfrom(2048)
            print("  udp %s:%d %-18s REPLY %d bytes from %s:%d" % (
                tgt[0], tgt[1], label, len(data), addr[0], addr[1]))
            report("udp payload", data, False)
        except socket.timeout:
            print("  udp %s:%d %-18s no reply" % (tgt[0], tgt[1], label))
    except OSError as e:
        print("  udp %s:%d %-18s %s" % (tgt[0], tgt[1], label, e))
    s.close()


def phase_tcp():
    print("=== TCP %s:%d ===" % TCP)
    tcp_case("mirror hello [1][01]", [frame(b"\x01")], 3)
    tcp_case("mirror hello [1][00]", [frame(b"\x00")], 3)
    tcp_case("name alone (long wait)", [frame(NAME.encode())], 8)
    tcp_case("name+token frames", [frame(NAME.encode()), frame(TOKEN.encode())], 4)
    tcp_case("mpack name", [frame(msgpack.packb(NAME))], 4)
    tcp_case("mpack {} empty", [frame(msgpack.packb({}))], 4)
    tcp_case("mpack {name,token}", [frame(msgpack.packb(
        {"name": NAME, "token": TOKEN}))], 4)
    tcp_case("mpack {token}", [frame(msgpack.packb({"token": TOKEN}))], 4)
    tcp_case("mpack str 'register'", [frame(msgpack.packb("register"))], 4)
    tcp_case("mpack u16 1", [frame(msgpack.packb(1))], 4)


def phase_udp():
    for tgt in UDPS:
        print("=== UDP %s:%d ===" % tgt)
        udp_case(tgt, "frame name", frame(NAME.encode()))
        udp_case(tgt, "frame token", frame(TOKEN.encode()))
        udp_case(tgt, "mpack map", frame(msgpack.packb(
            {"name": NAME, "token": TOKEN})))


def phase_http():
    print("=== HTTP :443 (TLS, no Connection hdr) ===")
    host = "34.175.83.169"
    ctx = ssl._create_unverified_context()
    for method, path, body, ctype in (
            ("GET", "/", None, None),
            ("POST", "/", json.dumps({"name": NAME, "token": TOKEN}),
             "application/json"),
            ("POST", "/register", json.dumps({"name": NAME, "token": TOKEN}),
             "application/json")):
        try:
            raw = socket.create_connection((host, 443), timeout=6)
            s = ctx.wrap_socket(raw, server_hostname="relay.local")
            hdrs = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, host)
            if ctype:
                hdrs += "Content-Type: %s\r\nContent-Length: %d\r\n" % (
                    ctype, len(body))
            hdrs += "\r\n"
            s.sendall(hdrs.encode() + (body.encode() if body else b""))
            data, closed = read_frames(s, 3)
            s.close()
            print("  %s %s -> %r" % (method, path, data[:300]))
        except OSError as e:
            print("  %s %s -> %s" % (method, path, e))


if __name__ == "__main__":
    args = sys.argv[1:] or ["tcp", "udp", "http"]
    if "tcp" in args:
        phase_tcp()
    if "udp" in args:
        phase_udp()
    if "http" in args:
        phase_http()
