#!/usr/bin/env python3
"""ws_session.py -- minimal WebSocket client against the relay :443.

  python ws_session.py            # listen only
  python ws_session.py json1 ...  # send candidates (one conn each)

Candidates: json1 (name+token), json2 (name+sid+token+side),
mpack1 (map name+token), mpack2 (array [name,token]), raw (name text),
cmd1 ({"cmd":"register",...}).
"""
import base64
import json
import os
import socket
import ssl
import struct
import sys
import time

import msgpack

SPEC_FILE = r"C:\Users\Administrator\Documents\Default Project\work\relay_spec.json"
spec = json.load(open(SPEC_FILE, encoding="utf-8"))
NAME, TOKEN, SID, SIDE = (spec["name"], spec["token"], spec["sid"],
                          spec["side"])

HOST = "34.175.83.169"
PORT = 443


def redact(b):
    if isinstance(b, bytes):
        try:
            s = b.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        s = b
    for secret in (NAME, TOKEN, SID):
        s = s.replace(secret, "<ours>")
    if len(s) > 300:
        s = s[:300] + "..."
    return s


def ws_connect():
    ctx = ssl._create_unverified_context()
    raw = socket.create_connection((HOST, PORT), timeout=6)
    s = ctx.wrap_socket(raw, server_hostname="relay.local")
    key = base64.b64encode(os.urandom(16)).decode()
    req = ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\n"
           "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
           "Sec-WebSocket-Key: %s\r\n\r\n" % (HOST, key))
    s.sendall(req.encode())
    s.settimeout(4)
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    if b" 101 " not in head.split(b"\r\n")[0]:
        raise OSError("no 101: %r" % head[:120])
    return s, rest


def ws_send(s, payload, binary=False):
    op = 0x82 if binary else 0x81
    mask = os.urandom(4)
    ln = len(payload)
    hdr = bytes([op])
    if ln < 126:
        hdr += bytes([0x80 | ln])
    elif ln < 65536:
        hdr += bytes([0x80 | 126]) + struct.pack(">H", ln)
    else:
        hdr += bytes([0x80 | 127]) + struct.pack(">Q", ln)
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(ln))
    s.sendall(hdr + mask + masked)


def ws_recv_frames(s, initial, wait=3.0, pong=True):
    """returns list of (opcode, payload)"""
    buf = initial
    frames = []
    t0 = time.time()
    s.settimeout(0.5)
    while time.time() - t0 < wait:
        while len(buf) >= 2:
            b0, b1 = buf[0], buf[1]
            op = b0 & 0x0F
            masked = b1 & 0x80
            ln = b1 & 0x7F
            idx = 2
            if ln == 126:
                if len(buf) < 4:
                    break
                ln = struct.unpack(">H", buf[2:4])[0]
                idx = 4
            elif ln == 127:
                if len(buf) < 10:
                    break
                ln = struct.unpack(">Q", buf[2:10])[0]
                idx = 10
            if masked:
                if len(buf) < idx + 4:
                    break
                mk = buf[idx:idx + 4]
                idx += 4
            if len(buf) < idx + ln:
                break
            p = buf[idx:idx + ln]
            if masked:
                p = bytes(p[i] ^ mk[i % 4] for i in range(ln))
            buf = buf[idx + ln:]
            if op == 0x9 and pong:            # ping -> pong
                mask = os.urandom(4)
                hdr = bytes([0x8A, 0x80 | len(p)])
                s.sendall(hdr + mask + bytes(
                    p[i] ^ mask[i % 4] for i in range(len(p))))
                continue
            if op == 0x8:
                frames.append((op, p))
                return frames, True
            frames.append((op, p))
        try:
            d = s.recv(65536)
            if not d:
                return frames, True
            buf += d
        except socket.timeout:
            continue
        except OSError:
            return frames, True
    return frames, False


def describe_frame(op, p):
    if op == 1:
        t = redact(p)
        return "TEXT: %r" % t
    if op == 2:
        try:
            obj = msgpack.unpackb(p, raw=False, strict_map_key=False)
            return "BIN msgpack: %s" % redact(json.dumps(obj, default=str))
        except Exception:
            return "BIN %d bytes: %s" % (len(p), p[:60].hex())
    return "op%d: %s" % (op, p[:40].hex())


def session(label, payload, binary, wait=3.0, listen_first=2.0):
    try:
        s, initial = ws_connect()
    except OSError as e:
        print("  %-12s connect: %s" % (label, e))
        return
    frames, closed = ws_recv_frames(s, initial, listen_first)
    print("  %-12s post-upgrade listen: %s" % (
        label, [describe_frame(o, p) for o, p in frames] or "silence"))
    if payload is not None:
        ws_send(s, payload, binary)
        frames2, closed2 = ws_recv_frames(s, b"", wait)
        print("  %-12s after send: %s" % (
            label, [describe_frame(o, p) for o, p in frames2]
            or ("nothing" + (" (closed)" if closed2 else ""))))
    s.close()


def build(kind):
    if kind == "json1":
        return json.dumps({"name": NAME, "token": TOKEN}).encode(), False
    if kind == "json2":
        return json.dumps({"name": NAME, "sid": SID, "token": TOKEN,
                           "side": SIDE}).encode(), False
    if kind == "mpack1":
        return msgpack.packb({"name": NAME, "token": TOKEN}), True
    if kind == "mpack2":
        return msgpack.packb([NAME, TOKEN]), True
    if kind == "raw":
        return NAME.encode(), False
    if kind == "cmd1":
        return json.dumps({"cmd": "register", "name": NAME,
                           "token": TOKEN}).encode(), False
    if kind == "mpack_cmd":
        return msgpack.packb({"cmd": "register", "name": NAME,
                              "token": TOKEN}), True
    raise SystemExit("unknown candidate %s" % kind)


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        session("listen", None, False, listen_first=5.0)
    for k in args:
        payload, binary = build(k)
        session(k, payload, binary)
