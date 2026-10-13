#!/usr/bin/env python3
"""ws_probe.py -- walk the :443 Upgrade handshake via its own error messages.

The server names the offending/missing header in each 400.  Iterate
until 101 Switching Protocols (or a new error teaches the next step).
"""
import base64
import os
import socket
import ssl
import sys
import time

HOST = "34.175.83.169"
PORT = 443
SNI = "relay.local"


def connect():
    ctx = ssl._create_unverified_context()
    raw = socket.create_connection((HOST, PORT), timeout=6)
    return ctx.wrap_socket(raw, server_hostname=SNI)


def req(headers_extra, path="/", method="GET"):
    s = connect()
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s" % HOST]
    lines += headers_extra
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode()
    s.sendall(raw)
    s.settimeout(3)
    out = b""
    t0 = time.time()
    while time.time() - t0 < 3:
        try:
            d = s.recv(4096)
            if not d:
                break
            out += d
            if b"\r\n\r\n" in out and (b"101" in out[:20]
                                       or b"Content-Length:" in out):
                # try to read body fully
                head, _, body = out.partition(b"\r\n\r\n")
                cl = None
                for hl in head.split(b"\r\n"):
                    if hl.lower().startswith(b"content-length:"):
                        cl = int(hl.split(b":")[1])
                if cl is not None and len(body) < cl:
                    s.settimeout(2)
                    try:
                        out += s.recv(cl - len(body))
                    except OSError:
                        pass
                break
        except socket.timeout:
            break
        except OSError:
            break
    s.close()
    return out


def show(label, out):
    head = out.split(b"\r\n\r\n")[0].decode(errors="replace")
    body = out.split(b"\r\n\r\n")[1] if b"\r\n\r\n" in out else b""
    status = head.split("\r\n")[0]
    print("  %-30s %s | %r" % (label, status, body[:140]))
    return status


def main():
    key = base64.b64encode(os.urandom(16)).decode()
    ws_standard = [
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: %s" % key,
    ]
    cases = [
        ("minimal upgrade", ["Connection: Upgrade", "Upgrade: websocket"]),
        ("upgrade + conn swap", ["Upgrade: websocket",
                                 "Connection: Upgrade"]),
        ("no sec-ws-key", ws_standard[:2]),
        ("full standard ws", ws_standard),
        ("upgrade: h2c", ["Connection: Upgrade", "Upgrade: h2c"]),
        ("upgrade: pesms", ["Connection: Upgrade", "Upgrade: pesms"]),
        ("upgrade: relay", ["Connection: Upgrade", "Upgrade: relay"]),
        ("upgrade: tcp", ["Connection: Upgrade", "Upgrade: tcp"]),
    ]
    only = sys.argv[1:]
    for label, hdrs in cases:
        if only and not any(o in label for o in only):
            continue
        try:
            out = req(hdrs)
            st = show(label, out)
            if "101" in st:
                print("  >>> UPGRADE ACCEPTED with: %s" % hdrs)
                break
        except OSError as e:
            print("  %-30s ERROR %s" % (label, e))
        time.sleep(0.2)


if __name__ == "__main__":
    main()
