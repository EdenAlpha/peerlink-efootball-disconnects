#!/usr/bin/env python3
"""relay_probe2.py -- learn the relay registration framing.

Spec captured from room session (LOCAL file, never print raw values):
  name/region/ip candidates + token.

Phase 1: TLS :443 -- ALPN?  server-first bytes?
Phase 2: TCP :5736 -- after server hello 00 01, try candidate
         registration framings (raw name / token / len-prefix / msgpack).
Phase 3: UDP :5735 -- same payloads as datagrams.

Every reply is printed hex+ascii; no credentials in output (name/token
are redacted to sid-prefix + lengths only).
"""
import base64
import json
import socket
import ssl
import struct
import sys
import time

SPEC_FILE = r"C:\Users\Administrator\Documents\Default Project\work\relay_spec.json"


def load_spec():
    with open(SPEC_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def tag(s):
    """redact: keep shape only."""
    if isinstance(s, str):
        return "<str len=%d>" % len(s)
    return "<%s>" % type(s).__name__


def recv_some(sock, wait=2.0, n=512):
    sock.settimeout(wait)
    out = b""
    t0 = time.time()
    while time.time() - t0 < wait:
        try:
            d = sock.recv(n)
            if not d:
                return out, True
            out += d
            if len(out) >= 4096:
                break
        except socket.timeout:
            break
        except OSError:
            break
    return out, False


def show(label, data, closed=False):
    if not data:
        print("  %-34s %s" % (label, "no reply" + (" (closed)" if closed else "")))
        return
    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in data[:60])
    print("  %-34s %d bytes: %s |%s|" % (label, len(data), data[:40].hex(), asc))
    if closed:
        print("    (server closed after reply)")


def phase1_tls(spec):
    print("=== phase 1: TLS :443 candidates ===")
    ip, port = "34.175.83.169", 443
    ctx = ssl._create_unverified_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        raw = socket.create_connection((ip, port), timeout=6)
        s = ctx.wrap_socket(raw, server_hostname="relay.local")
        print("  TLS ok, ALPN=%r proto=%s" % (s.selected_alpn_protocol(), s.version()))
        data, closed = recv_some(s, 3.0)
        show("server-first over TLS", data, closed)
        if not data:
            # send http/2 preface just in case
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            data, closed = recv_some(s, 2.0)
            show("after h2 preface", data, closed)
        s.close()
    except OSError as e:
        print("  TLS 443: %s" % e)


def probe_tcp_one(ip, port, payload, wait=2.0, expect_hello=True):
    s = socket.create_connection((ip, port), timeout=6)
    s.settimeout(3)
    hello = b""
    if expect_hello:
        try:
            hello = s.recv(64)
        except socket.timeout:
            pass
    if payload:
        s.sendall(payload)
    data, closed = recv_some(s, wait)
    s.close()
    return hello, data, closed


def phase2_tcp(spec):
    print("=== phase 2: TCP :5736 registration framings ===")
    ip, port = "34.175.83.169", 5736
    name = spec["name"].encode()
    token = spec["token"].encode()
    sid = spec["sid"].encode()

    import msgpack
    cands = [
        ("raw name", name),
        ("raw token", token),
        ("raw sid", sid),
        ("u16be+name", struct.pack(">H", len(name)) + name),
        ("u16be+token", struct.pack(">H", len(token)) + token),
        ("u16le+name", struct.pack("<H", len(name)) + name),
        ("u32be+name", struct.pack(">I", len(name)) + name),
        ("msgpack [name,token]", msgpack.packb([spec["name"], spec["token"]])),
        ("u16be+msgpack[name,token]", struct.pack(">H", 0) + b""),
        ("ver 0001 + u16 name", b"\x00\x01" + struct.pack(">H", len(name)) + name),
        ("u8 type01 + name", b"\x01" + name),
        ("msgpack {name,token}",
         msgpack.packb({"name": spec["name"], "token": spec["token"]})),
    ]
    # fix the placeholder
    import msgpack as mp
    cands[8] = ("u16be+mpack[name,token]",
                struct.pack(">H", 1) + mp.packb([spec["name"], spec["token"]]))

    for label, payload in cands:
        try:
            hello, data, closed = probe_tcp_one(ip, port, payload)
            h = hello.hex() if hello else "-"
            print("  send %-24s hello=%s" % (label, h))
            show("  reply", data, closed)
        except OSError as e:
            print("  send %-24s ERROR %s" % (label, e))
        time.sleep(0.3)


def phase3_udp(spec):
    print("=== phase 3: UDP :5735 datagrams ===")
    ip, port = "34.175.250.31", 5735
    ip2, port2 = "34.175.83.169", 5736   # udp to 5736 too
    import msgpack
    name = spec["name"].encode()
    token = spec["token"].encode()
    cands = [
        ("raw name", name),
        ("raw token", token),
        ("u16be+name", struct.pack(">H", len(name)) + name),
        ("msgpack name", msgpack.packb(spec["name"])),
        ("msgpack {name,token}", msgpack.packb({"name": spec["name"],
                                                "token": spec["token"]})),
        ("stun-ish", b"\x00\x01\x00\x00" + b"\x21\x12\xa4\x42" + b"\x00" * 12),
    ]
    for tgt in ((ip, port), (ip2, port2)):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.5)
        print("  -- target %s:%d" % tgt)
        for label, payload in cands:
            try:
                s.sendto(payload, tgt)
                t0 = time.time()
                data, addr = s.recvfrom(1024)
                show("udp %s" % label,
                     data + b"  from %s:%d" % (addr[0].encode(), addr[1])
                     if False else data)
            except socket.timeout:
                print("  udp %-24s no reply" % label)
            except OSError as e:
                print("  udp %-24s %s" % (label, e))
            time.sleep(0.2)
        s.close()


def main():
    spec = load_spec()
    print("spec: name=%s sid=%d token=%s endpoints=%s"
          % (tag(spec["name"]), len(spec.get("sid", "")), tag(spec["token"]),
             spec.get("endpoint_hint", "?")))
    if "--tls" in sys.argv:
        phase1_tls(spec)
    elif "--tcp" in sys.argv:
        phase2_tcp(spec)
    elif "--udp" in sys.argv:
        phase3_udp(spec)
    else:
        phase1_tls(spec)
        phase2_tcp(spec)
        phase3_udp(spec)


if __name__ == "__main__":
    main()
