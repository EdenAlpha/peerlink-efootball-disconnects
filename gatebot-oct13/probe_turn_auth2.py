#!/usr/bin/env python3
"""probe_turn_auth2.py -- turn the 401 into an allocation.

dump_turn401.py settled what the challenge actually contains:

    ERROR-CODE   0x0009 len=16  class=4 number=1  (401 Unauthorized)
    NONCE        0x0015 len=16  '59ec16d34a7ee2e4'
    REALM        0x0014 len=0    -- genuinely zero-length, not a parse bug
    SOFTWARE     0x8022 len=62  '34.182.151.194:31542,...,0'
    GOOGLE-SESSION-INFO 0x8028 len=4  '1af7a950'

So MD5(u ":" realm ":" pw) collapses to MD5(u "::" pw), and probe_turn_auth.py
already tried that across many usernames -- still 401.  What it never did was
echo the Google-specific 0x8028 attribute back, which is the one attribute on
this server that nothing in RFC 5389/5766 accounts for.

This sweeps username form x key derivation x whether 0x8028 is echoed, and
prints only the combinations that get past 401.

  python probe_turn_auth2.py
  python probe_turn_auth2.py --show-error
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

from room1 import Gate, load_capture, login, PACE, describe   # noqa: E402

TURN_HOST, TURN_PORT, SNI = "130.211.8.132", 443, "pes20.turn.konami.com"
MAGIC = 0x2112A442
A_SESSION = 0x8028

ATTRN = {0x0006: "USERNAME", 0x0014: "REALM", 0x0015: "NONCE",
         0x0009: "ERROR-CODE", 0x0020: "XOR-RELAYED-ADDR",
         0x0016: "XOR-PEER-ADDR", 0x0008: "MESSAGE-INTEGRITY",
         0x0019: "FINGERPRINT", 0x8022: "SOFTWARE", 0x0011: "REQ-TRANSPORT",
         0x000D: "LIFETIME", 0x8028: "GOOGLE-SESSION-INFO"}


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


def build(method, attrs, key, txx):
    body = b""
    for at, v in attrs:
        body += struct.pack("!HH", at, len(v)) + v + b"\x00" * ((4 - len(v) % 4) % 4)
    pre = struct.pack("!HHI", method, len(body) + 24, MAGIC) + txx + body
    mac = hmac.new(key, pre, hashlib.sha1).digest()
    return pre + struct.pack("!HH", 0x0008, 20) + mac


def challenge():
    """anonymous Allocate -> (nonce, session_info, software)"""
    ss = tls()
    t = txid()
    ss.sendall(struct.pack("!HHI", 0x0003, 0, MAGIC) + t)
    d = ss.recv(4096)
    ss.close()
    _mt, at = parse(d)
    g = next((raw for n, _v, raw in at if n == "NONCE"), b"")
    s = next((raw for n, _v, raw in at
              if n == "GOOGLE-SESSION-INFO"), b"")
    sw = next((raw for n, _v, raw in at if n == "SOFTWARE"), b"")
    return g, s, sw


def gate():
    """-> (id, pw, user_id, limit_used)

    turn_time_limit is the credential's lifetime in seconds and the returned
    turn_account.id is its unix EXPIRY.  With the 0 we were sending, id was
    already in the past by the time we signed anything, which is why every
    Allocate came back 401 no matter how the MESSAGE-INTEGRITY key was built.
    """
    reqs, _ = load_capture()
    g = Gate()
    ok, r = login(g, reqs)
    if not ok:
        raise RuntimeError("login failed: %s" % describe(r))
    m = g.envelope("CMD_GET_TURN_SERVER_LIST")
    m["turn_account_param"] = ""
    m["turn_time_limit"] = 3600
    tr = g.send(m, timeout=15)
    if tr.get("result") != "NOERR":
        raise RuntimeError("turn list: %s" % tr.get("result"))
    acc = tr.get("turn_account") or {}
    return (str(acc.get("id", "")), str(acc.get("pw", "")),
            str(g.uid), 3600)


def attempt(user, key, nonce, sess, echo_sess, echo_sw, sw, realm=b""):
    attrs = [(0x0006, user.encode() if isinstance(user, str) else user)]
    if realm is not None:
        attrs.append((0x0014, realm))
    if echo_sess and sess:
        attrs.append((A_SESSION, sess))
    if echo_sw and sw:
        attrs.append((0x8022, sw))
    attrs.append((0x0015, nonce))
    attrs.append((0x0011, bytes([17, 0, 0, 0])))
    attrs.append((0x000D, struct.pack("!I", 600)))
    ss = tls()
    t = txid()
    ss.sendall(build(0x0003, attrs, key, t))
    d = ss.recv(4096)
    ss.close()
    return parse(d)


def main() -> int:
    show_err = "--show-error" in sys.argv
    print("=== gate: CMD_GET_TURN_SERVER_LIST (turn_time_limit=3600) ===")
    exp, pw, uid, lim = gate()
    ts = int(exp) if exp.isdigit() else 0
    print("  turn_account.id = %s (expiry in %ds)   user_id = %s   pw %d chars"
          % (exp, ts - int(time.time()), uid, len(pw)))
    time.sleep(PACE)

    print("\n=== fetching a fresh challenge ===")
    nonce, sess, sw = challenge()
    print("  NONCE %r" % nonce.decode())
    print("  GOOGLE-SESSION-INFO %dB %s" % (len(sess), sess.hex()))
    print("  SOFTWARE %r" % sw.decode())
    if not nonce:
        print("  no NONCE, aborting")
        return 1

    try:
        pw_dec = base64.b64decode(pw + "=" * (-len(pw) % 4))
    except Exception:                                              # noqa: BLE001
        pw_dec = b""

    users = ["%s:%s" % (exp, uid), exp, uid, "%s:0" % exp,
             "%s:%s" % (uid, exp)]
    keys = [("MD5(u::pw)", lambda u: hashlib.md5(
                ("%s::%s" % (u, pw)).encode()).digest()),
            ("MD5(u::pwdec)", lambda u: hashlib.md5(
                ("%s::%s" % (u, pw_dec.decode("latin-1"))).encode()).digest()),
            ("pw-as-key", lambda u: pw.encode()),
            ("pwdec-as-key", lambda u: pw_dec)]

    print("\n=== %d usernames x %d keys x {sess echoed, not} x {sw echoed, not}"
          " ===" % (len(users), len(keys)))
    best = None
    seen = {}
    for u in users:
        for kl, kf in keys:
            for es in (True, False):
                for esw in (True, False):
                    try:
                        mt, at = attempt(u, kf(u), nonce, sess, es, esw, sw)
                    except Exception as e:                        # noqa: BLE001
                        print("  %-16s %-14s sess=%-5s sw=%-5s ERR %s"
                              % (u[:16], kl, es, esw, e))
                        continue
                    err = next((v for n, v, _ in at if n == "ERROR-CODE"), "?")
                    ok = mt == 0x0103
                    tag = (err, ok)
                    if ok:
                        print("  <<< ALLOCATED  user=%-16s key=%-14s "
                              "sess=%-5s sw=%-5s" % (u[:16], kl, es, esw))
                        for n, v, _ in at:
                            print("        %-22s %s" % (n, v))
                        if best is None:
                            best = (u, kl, es, esw)
                    elif show_err:
                        print("  %-16s %-14s sess=%-5s sw=%-5s %s"
                              % (u[:16], kl, es, esw, err))
                    seen[err] = seen.get(err, 0) + 1

    print("\n=== error census ===")
    for k, v in sorted(seen.items(), key=lambda x: -x[1]):
        print("  %-24s %d" % (k, v))
    print("\nRESULT: %s" % ("ALLOCATED %s" % (best,) if best
                            else "no combination authenticated"))
    return 0 if best else 1


if __name__ == "__main__":
    raise SystemExit(main())
