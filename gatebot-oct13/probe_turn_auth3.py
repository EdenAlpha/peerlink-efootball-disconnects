#!/usr/bin/env python3
"""probe_turn_auth3.py -- combine everything the last three probes learned.

probe_turn_auth.py   : same-connection nonce, but turn_time_limit=0
                       -> password already expired -> 401 Unauthorized
probe_turn_auth2.py  : live password, but the NONCE came from a DIFFERENT
                       TLS connection -> 4038 Stale Nonce (438)
                       and echoing GOOGLE-SESSION-INFO (0x8028) -> read timeout
dump_turn401.py      : REALM is genuinely zero-length, so MD5(u:realm:p)
                       collapses to MD5(u "::" pw)

This is the combination none of them tested together: a live credential, the
NONCE taken from the very connection the Allocate goes out on, and a key
derivation actually evaluated (probe_turn_auth2 never reached that stage --
every row stopped at 438 Stale Nonce or a timeout).  It sweeps username x
key x realm x whether the MESSAGE-INTEGRITY attribute counts toward the
header length, and prints only what is not 4001 Unauthorized.

  python probe_turn_auth3.py
"""
import base64
import hashlib
import hmac
import os
import socket
import ssl
import struct
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import Gate, load_capture, login, PACE, describe       # noqa: E402

TURN_HOST, TURN_PORT, SNI = "130.211.8.132", 443, "pes20.turn.konami.com"
MAGIC = 0x2112A442
LIMIT = 3600                       # turn_time_limit: 0 expired in 1 second

ATTRN = {0x0006: "USERNAME", 0x0014: "REALM", 0x0015: "NONCE",
         0x0009: "ERROR-CODE", 0x0020: "XOR-RELAYED-ADDR",
         0x0016: "XOR-PEER-ADDR", 0x0008: "MESSAGE-INTEGRITY",
         0x0019: "FINGERPRINT", 0x8022: "SOFTWARE", 0x0011: "REQ-TRANSPORT",
         0x000D: "LIFETIME", 0x8028: "GOOGLE-SESSION-INFO",
         0x0022: "RESERVATION-TOKEN", 0x8030: "DATA"}


def tls():
    raw = socket.create_connection((TURN_HOST, TURN_PORT), timeout=6)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(raw, server_hostname=SNI)
    ss.settimeout(6)
    return ss


def txid():
    return os.urandom(12)


def parse(d):
    if len(d) < 20:
        return None, []
    mt = struct.unpack("!H", d[:2])[0]
    ml = struct.unpack("!H", d[2:4])[0]
    out, i = [], 20
    while i + 4 <= min(20 + ml, len(d)):
        at, al = struct.unpack("!HH", d[i:i + 4])
        v = d[i + 4:i + 4 + al]
        nm = ATTRN.get(at, "0x%04x" % at)
        if at == 0x0009 and len(v) >= 4:
            w = struct.unpack("!I", v[:4])[0]
            val = "[%d%03d] %s" % ((w >> 8) & 0x7, w & 0xFF,
                                   v[4:].decode("utf-8", "replace"))
        elif at in (0x0006, 0x0014, 0x0015, 0x8022):
            val = repr(v.decode("utf-8", "replace"))
        elif at in (0x0020, 0x0016) and len(v) >= 8:
            port = struct.unpack("!H", v[2:4])[0] ^ (MAGIC >> 16)
            ip = socket.inet_ntoa(bytes(
                a ^ b for a, b in zip(v[4:8], struct.pack("!I", MAGIC))))
            val = "%s:%d" % (ip, port)
        else:
            val = "%dB %s" % (len(v), v[:12].hex())
        out.append((nm, val, v))
        i += 4 + al + (4 - al % 4) % 4
    return mt, out


def build(method, attrs, key, txx, hdr_len=True):
    body = b""
    for at, v in attrs:
        body += struct.pack("!HH", at, len(v)) + v + b"\x00" * ((4 - len(v) % 4) % 4)
    # RFC 5389: the header length INCLUDES the MESSAGE-INTEGRITY attribute,
    # and the HMAC covers header+body up to that point.  Older stacks exclude
    # it, so both are tried.
    n = len(body) + 24 if hdr_len else len(body)
    pre = struct.pack("!HHI", method, n, MAGIC) + txx + body
    mac = hmac.new(key, pre, hashlib.sha1).digest()
    return pre + struct.pack("!HH", 0x0008, 20) + mac


def gate():
    reqs, _ = load_capture()
    g = Gate()
    ok, r = login(g, reqs)
    if not ok:
        raise RuntimeError("login failed: %s" % describe(r))
    m = g.envelope("CMD_GET_TURN_SERVER_LIST")
    m["turn_account_param"] = ""
    m["turn_time_limit"] = LIMIT
    tr = g.send(m, timeout=15)
    if tr.get("result") != "NOERR":
        raise RuntimeError("turn list: %s" % tr.get("result"))
    acc = tr.get("turn_account") or {}
    return str(acc.get("id", "")), str(acc.get("pw", "")), str(g.uid)


def attempt(user, key, realm=b"", hdr_len=True):
    """ONE TLS connection: anonymous probe for a nonce, then the signed
    Allocate on that same connection.  A nonce taken from a different
    connection comes back 438 Stale Nonce, which is what killed
    probe_turn_auth2.py."""
    ss = tls()
    try:
        ss.sendall(struct.pack("!HHI", 0x0003, 0, MAGIC) + txid())
        d = ss.recv(4096)
        _mt, at = parse(d)
        nonce = next((raw for n, _v, raw in at if n == "NONCE"), b"")
        if not nonce:
            return None, []
        attrs = [(0x0006, user.encode())]
        attrs.append((0x0014, realm))           # server's REALM is 0 length
        attrs.append((0x0015, nonce))
        attrs.append((0x0011, bytes([17, 0, 0, 0])))
        attrs.append((0x000D, struct.pack("!I", 600)))
        ss.sendall(build(0x0003, attrs, key, txid(), hdr_len))
        d = ss.recv(4096)
    finally:
        try:
            ss.close()
        except Exception:                                        # noqa: BLE001
            pass
    return parse(d)


def main() -> int:
    print("=== gate: CMD_GET_TURN_SERVER_LIST (turn_time_limit=%d) ===" % LIMIT)
    exp, pw, uid = gate()
    ts = int(exp) if exp.isdigit() else 0
    print("  turn_account.id = %s  expiry in %ds   user_id = %s   pw %d chars"
          % (exp, ts - int(time.time()), uid, len(pw)))
    time.sleep(PACE)

    try:
        pw_dec = base64.b64decode(pw + "=" * (-len(pw) % 4))
    except Exception:                                              # noqa: BLE001
        pw_dec = b""

    users = [("%s" % exp, "id=expiry"),
             ("%s:%s" % (exp, uid), "expiry:uid"),
             ("%s:0" % exp, "expiry:0"),
             (uid, "uid"),
             ("%s:%s" % (uid, exp), "uid:expiry")]
    keys = [("MD5(u::pw)", lambda u: hashlib.md5(
                ("%s::%s" % (u, pw)).encode()).digest()),
            ("MD5(u::pwdec)", lambda u: hashlib.md5(
                ("%s::%s" % (u, pw_dec.decode("latin-1"))).encode()).digest()),
            ("pw-as-key", lambda u: pw.encode()),
            ("pwdec-as-key", lambda u: pw_dec)]
    realms = [(b"", "realm=''"),
              (b"turn.konami.com", "realm=turn"),
              (SNI.encode(), "realm=sni")]

    total = len(users) * len(keys) * len(realms) * 2
    print("\n=== %d combos: users x keys x realm x MI-len-in-header,"
          " same-connection nonce ===" % total)
    hits = []
    census = {}
    shown = 0
    for u, ulab in users:
        for kl, kf in keys:
            for rb, rlab in realms:
                for hdr in (True, False):
                    lbl = "%-11s %-13s %-13s hdr=%-5s" % (ulab, kl, rlab, hdr)
                    try:
                        mt, at = attempt(u, kf(u), rb, hdr)
                    except Exception as e:                        # noqa: BLE001
                        print("  %-52s ERR %s" % (lbl, e))
                        continue
                    if mt == 0x0103:
                        print("  %-52s <<< ALLOCATED" % lbl)
                        for n, v, _ in at:
                            print("        %-22s %s" % (n, v))
                        hits.append((lbl, at))
                        continue
                    e = next((v for n, v, _ in at if n == "ERROR-CODE"),
                             "no reply (method=%s)" % (mt,))
                    census[e] = census.get(e, 0) + 1
                    if e != "[4001] Unauthorized":
                        print("  %-52s %s" % (lbl, e))
                        shown += 1

    print("\n=== census (%d combos) ===" % total)
    for k, v in sorted(census.items(), key=lambda x: -x[1]):
        print("  %-24s %d" % (k, v))
    if shown == 0 and not hits:
        print("\n  every combo -> 4001 Unauthorized: the MESSAGE-INTEGRITY\n"
              "  key is wrong, not the nonce and not the expiry.")
    print("\nRESULT: %s" % ("ALLOCATED" if hits else "still no allocation"))
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
