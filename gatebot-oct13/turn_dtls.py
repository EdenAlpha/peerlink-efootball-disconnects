#!/usr/bin/env python3
"""turn_dtls.py -- authenticate the Konami TURN allocation, then run the DTLS
cookie exchange against the rendezvous it issues.

Why: the DTLS front-end answers flight 1 (hello_verify) but drops flight 2
(cookie echo), even though the cookie round-trips byte-exactly.  The STUN
Allocate on the same host returns 401 Unauthorized with a NONCE, i.e. it
WANTS the long-term-credential allocation completed.  The working hypothesis
is that the rendezvous only becomes usable for a source that holds a live
allocation -- which is also, on its own, a server-observable session we hold
open across the match.

  gate: CMD_GET_TURN_SERVER_LIST {"turn_account_param":"","turn_time_limit":0}
        -> turn_server_list ip:port, turn_account {id, pw, origin}
  turn: TCP+TLS 443 -> Allocate -> 401 + NONCE + REALM
             -> Allocate + USERNAME + NONCE + REQUESTED-TRANSPORT(udp)
                + MESSAGE-INTEGRITY   (key = MD5(u ":" realm ":" pw))
        -> 0103 Allocate-Success {XOR-RELAYED-ADDR, LIFETIME, SOFTWARE}
  dtls: ClientHello -> hello_verify -> ClientHello+cookie -> server flight

Credentials never printed; only attributes and addresses are.

  python turn_dtls.py
  python turn_dtls.py --keep 30     hold the allocation alive N seconds
"""
import hashlib
import hmac
import socket
import ssl
import struct
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import dtls_live as D                                          # noqa: E402
from room1 import Gate, load_capture, login, PACE, describe     # noqa: E402

MAGIC = 0x2112A442
A = {0x0006: "USERNAME", 0x0014: "REALM", 0x0015: "NONCE",
     0x0009: "ERROR-CODE", 0x000A: "UNKNOWN-ATTRS", 0x000D: "LIFETIME",
     0x0020: "XOR-RELAYED-ADDR", 0x0016: "XOR-PEER-ADDR",
     0x0008: "MESSAGE-INTEGRITY", 0x0019: "FINGERPRINT",
     0x8022: "SOFTWARE", 0x0011: "REQUESTED-TRANSPORT",
     0x8028: "0x8028", 0x0012: "PEER-ADDRESS"}


def stun(method, attrs, txid, with_mi=None):
    """attrs: list of (type, bytes).  with_mi=(key,) appends MESSAGE-INTEGRITY
    computed per RFC 5389 s15.4."""
    body = b""
    for at, v in attrs:
        pad = (4 - len(v) % 4) % 4
        body += struct.pack("!HH", at, len(v)) + v + b"\x00" * pad
    total = len(body) + (24 if with_mi else 0)     # MI attr = 4 hdr + 20 mac
    head = struct.pack("!HHI", method, total, MAGIC) + txid
    if with_mi:
        mac = hmac.new(with_mi[0], head + body, hashlib.sha1).digest()
        body += struct.pack("!HH", 0x0008, 20) + mac
    return head + body


def parse(d):
    if len(d) < 20:
        return None, []
    mt, ml = struct.unpack("!HH", d[:4])
    out, i = [], 20
    while i + 4 <= min(20 + ml, len(d)):
        at, al = struct.unpack("!HH", d[i:i + 4])
        v = d[i + 4:i + 4 + al]
        nm = A.get(at, "0x%04x" % at)
        if at == 0x0009 and len(v) >= 4:
            raw = struct.unpack("!I", v[:4])[0]
            code = (raw >> 16) * 1000 + (raw & 0xFF)
            val = "[%d] %s" % (code, v[4:].decode("utf-8", "replace"))
        elif at in (0x0014, 0x0015, 0x0006, 0x8022):
            val = v.decode("utf-8", "replace")
        elif at in (0x0020, 0x0016, 0x0012) and len(v) >= 8:
            fam = v[1]
            port = struct.unpack("!H", v[2:4])[0] ^ (MAGIC >> 16)
            if fam == 1:
                ip = socket.inet_ntoa(bytes(a ^ b for a, b in
                                            zip(v[4:8], struct.pack("!I", MAGIC))))
                val = "%s:%d" % (ip, port)
            else:
                val = "v6 (%dB)" % len(v)
        elif at == 0x000D:
            val = "%ds" % struct.unpack("!I", v[:4])[0] if len(v) >= 4 else "?"
        else:
            val = "%dB" % len(v)
        out.append((nm, val, v))
        i += 4 + al + (4 - (al % 4)) % 4
    return mt, out


def tls():
    raw = socket.create_connection((D.TURN_HOST, D.TURN_PORT), timeout=6)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(raw, server_hostname=D.SNI)
    ss.settimeout(6)
    return ss


def turn_account():
    reqs, _ = load_capture()
    g = Gate()
    ok, r = login(g, reqs)
    if not ok:
        raise RuntimeError("login failed: %s" % describe(r))
    m = g.envelope("CMD_GET_TURN_SERVER_LIST")
    m["turn_account_param"] = ""
    m["turn_time_limit"] = 0
    tr = g.send(m, timeout=15)
    if tr.get("result") != "NOERR":
        raise RuntimeError("turn list: %s" % tr.get("result"))
    acc = tr.get("turn_account") or {}
    return g, acc.get("id", ""), acc.get("pw", ""), acc.get("origin", ""), \
        (tr.get("turn_server_list") or [])


def allocate(uid, pw, tries=3):
    """-> (attributes, txid, success_bool)"""
    txid = bytes.fromhex("0a0b0c0d0e0f101112131415")
    ss = tls()
    # 1. anonymous allocate -> 401 + NONCE
    ss.sendall(stun(0x0003, [], txid))
    d = ss.recv(4096)
    mt, at = parse(d)
    nonce = next((v for n, v, _ in at if n == "NONCE"), "")
    realm = next((v for n, v, _ in at if n == "REALM"), "")
    print("  pass 1 method=0x%04x %s" % (mt, fmt(at)))
    if not nonce:
        ss.close()
        return at, txid, False

    # 2. authenticated allocate (long-term credentials)
    key = hashlib.md5(("%s:%s:%s" % (uid, realm, pw)).encode()).digest()
    for attempt in range(tries):
        req = [(0x0006, uid.encode()),
               (0x0014, realm.encode()),
               (0x0015, nonce.encode()),
               (0x0011, bytes([17, 0, 0, 0])),      # requested: UDP
               (0x000D, struct.pack("!I", 600))]
        ss.sendall(stun(0x0003, req, txid, with_mi=(key,)))
        d = ss.recv(4096)
        mt, at = parse(d)
        print("  pass %d method=0x%04x %s" % (attempt + 2, mt, fmt(at)))
        err = next((v for n, v, _ in at if n == "ERROR-CODE"), "")
        if mt == 0x0103:                       # allocate success
            ss.close()
            return at, txid, True
        nonce2 = next((v for n, v, _ in at if n == "NONCE"), "")
        if not nonce2 or nonce2 == nonce:
            ss.close()
            return at, txid, False
        nonce = nonce2                         # 438 stale nonce -> retry
    ss.close()
    return at, txid, False


def fmt(at):
    return " ".join("%s=%s" % (n, (v if len(str(v)) < 90 else str(v)[:90] + ".."))
                    for n, v, _ in at)


def dtls(ip, port, label):
    print("\n  --- DTLS against %s:%d (%s) ---" % (ip, port, label))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    ch = D.captured_ch()
    recs, _ = D.parse_records(ch)
    recver = recs[0][1]
    _, _, body = D.parse_handshakes(recs)[0]
    f = D.parse_hs_body(body)
    s.sendto(ch, (ip, port))
    t0 = time.time()
    try:
        d, frm = s.recvfrom(4096)
    except socket.timeout:
        print("    flight1: timeout")
        s.close()
        return
    items = D.parse_handshakes(D.parse_records(d)[0])
    cookie = None
    for mt, _, b in items:
        if mt == 3 and len(b) >= 3:
            cookie = b[3:]
    print("    flight1: %dB %s (%dms)" % (len(d), D.HSN.get(items[0][0]),
                                          int((time.time() - t0) * 1000)))
    if not cookie:
        print("    no cookie")
        s.close()
        return
    f["cookie"] = cookie
    ch2 = D.build_ch(f, recver, mseq=1, rseq=1)
    got = b""
    for _ in range(5):
        s.sendto(ch2, (ip, port))
        s.settimeout(0.7)
        while True:
            try:
                got += s.recvfrom(8192)[0]
            except socket.timeout:
                break
        if got:
            break
        time.sleep(0.4)
    s.close()
    if not got:
        print("    flight2: no reply (%dB sent)" % len(ch2))
        return
    print("    flight2: %dB reply" % len(got))
    recs, _ = D.parse_records(got)
    for ct, ver, ep, _seq, body in recs:
        print("      rec type=0x%02x ver=0x%04x ep=%d len=%d" % (ct, ver, ep, len(body)))
    D.show_hs(D.parse_handshakes(recs))


def main() -> int:
    print("=== gate: CMD_GET_TURN_SERVER_LIST ===")
    g, uid, pw, origin, tsl = turn_account()
    print("  origin   %s" % origin)
    print("  account  id=%s pw=%s (%d endpoints)"
          % ("present" if uid else "MISSING",
             "present" if pw else "MISSING", len(tsl)))
    for e in tsl:
        print("    zone=%s %s:%s tls=%s"
              % (e.get("zone"), e.get("address"), e.get("port"),
                 e.get("tls_port")))
    time.sleep(PACE)

    print("\n=== TURN: STUN Allocate over TLS %s:%d ==="
          % (D.TURN_HOST, D.TURN_PORT))
    at, txid, ok = allocate(uid, pw)
    print("  -> %s" % ("ALLOCATED" if ok else "not allocated"))

    soft = next((v for n, v, _ in at if n == "SOFTWARE"), "")
    if soft:
        print("  SOFTWARE rendezvous: %s" % soft)
        host, _, port = soft.split(",")[0].rpartition(":")
        if port.isdigit():
            ip = socket.getaddrinfo(host, int(port), socket.AF_INET,
                                    socket.SOCK_DGRAM)[0][4][0]
            dtls(ip, int(port), "post-allocation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
