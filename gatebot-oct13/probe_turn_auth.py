#!/usr/bin/env python3
"""probe_turn_auth.py -- find the credential derivation Konami's TURN accepts.

Run #36 held a DTLS session open for the whole match (276/277 keepalives, no
errors, cipher identical to the capture) and still got DISCONN_HB -- but
`received: 0`: the server never pushed anything back.  Every STUN Allocate so
far has answered 401 Unauthorized even with turn_account id/pw supplied, so
the session we hold is anonymous and unlinked to our room.  The rendezvous
SOFTWARE string is issued per Allocate, which means an unauthenticated
Allocate hands out an endpoint nobody will correlate with our match.

This probes the credential schemes that could produce the right
MESSAGE-INTEGRITY, one fresh TLS connection per attempt, and reports which
one gets method=0x0103 (Allocate Success).

  python probe_turn_auth.py
  python probe_turn_auth.py --success-detail
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

ATTR = {0x0006: "USERNAME", 0x0014: "REALM", 0x0015: "NONCE",
        0x0009: "ERROR-CODE", 0x000A: "UNKNOWN-ATTRS", 0x000D: "LIFETIME",
        0x0020: "XOR-RELAYED-ADDR", 0x0016: "XOR-PEER-ADDR",
        0x0008: "MESSAGE-INTEGRITY", 0x0019: "FINGERPRINT",
        0x8022: "SOFTWARE", 0x0011: "REQUESTED-TRANSPORT",
        0x8028: "0x8028", 0x0012: "PEER-ADDRESS", 0x8030: "DATA",
        0x0024: "REQUESTED-ADDR-TYPE", 0x0022: "RESERVATION-TOKEN"}


def tls():
    raw = socket.create_connection((TURN_HOST, TURN_PORT), timeout=6)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(raw, server_hostname=SNI)
    ss.settimeout(6)
    return ss


def stun(method, attrs, txid, mi_key=None, mi_len_in_hdr=True):
    body = b""
    for at, v in attrs:
        pad = (4 - len(v) % 4) % 4
        body += struct.pack("!HH", at, len(v)) + v + b"\x00" * pad
    total = len(body)
    if mi_key is not None:
        total += 24 if mi_len_in_hdr else 0
    head = struct.pack("!HHI", method, total, MAGIC) + txid
    if mi_key is not None:
        # RFC 5389 s15.4: header length INCLUDES the MI attribute,
        # HMAC covers everything up to (not including) MI.
        if not mi_len_in_hdr:
            raw = struct.pack("!HHI", method, len(body), MAGIC) + txid + body
            mac = hmac.new(mi_key, raw, hashlib.sha1).digest()
        else:
            mac = hmac.new(mi_key, head + body, hashlib.sha1).digest()
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
        nm = ATTR.get(at, "0x%04x" % at)
        if at == 0x0009 and len(v) >= 4:
            rawv = struct.unpack("!I", v[:4])[0]
            code = ((rawv >> 8) & 0x7) * 1000 + (rawv & 0xFF)
            val = "[%d] %s" % (code, v[4:].decode("utf-8", "replace"))
        elif at in (0x0014, 0x0015, 0x0006, 0x8022):
            val = v.decode("utf-8", "replace")
        elif at in (0x0020, 0x0016, 0x0012) and len(v) >= 8:
            fam = v[1]
            port = struct.unpack("!H", v[2:4])[0] ^ (MAGIC >> 16)
            if fam == 1:
                ip = socket.inet_ntoa(bytes(
                    a ^ b for a, b in zip(v[4:8], struct.pack("!I", MAGIC))))
                val = "%s:%d" % (ip, port)
            else:
                val = "v6 (%dB)" % len(v)
        elif at == 0x000D and len(v) >= 4:
            val = "%ds" % struct.unpack("!I", v[:4])[0]
        else:
            val = "%dB" % len(v)
        out.append((nm, val, v))
        i += 4 + al + (4 - (al % 4)) % 4
    return mt, out


def gate_account():
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
    return g, str(acc.get("id", "")), str(acc.get("pw", "")), str(g.uid)


def candidates(exp, pw, uid, realm=""):
    """(label, username, realm_bytes, hmac_key).

    turn_account.id is a unix *expiry* timestamp (1791871821 = today), not a
    user id.  That is the coturn/TURN-REST shape: the username is
    "<expiry>:<user>" and the gate pre-derived the password.  Verification
    itself then uses the ordinary long-term key MD5(user ":" realm ":" pw).
    """
    users = [("%s:%s" % (exp, uid), "exp:uid"),
             (uid, "uid"),
             (exp, "exp"),
             ("%s:%s" % (uid, exp), "uid:exp"),
             ("0", "zero")]
    realms = [(realm, "r=''"),
              ("turn.konami.com", "r=turn"),
              (SNI, "r=sni")]
    out = []
    for uname, ulabel in users:
        for rtxt, rlabel in realms:
            key = hashlib.md5(
                ("%s:%s:%s" % (uname, rtxt, pw)).encode()).digest()
            out.append(("%-7s %s" % (ulabel, rlabel),
                        uname.encode(), rtxt.encode(), key))
    # raw base64 password used directly as the HMAC key
    try:
        raw = base64.b64decode(pw + "=" * (-len(pw) % 4))
        out.append(("raw-pw  r=''", ("%s:%s" % (exp, uid)).encode(),
                    realm.encode(), raw))
        out.append(("raw-pw  uid  ", uid.encode(), realm.encode(), raw))
        out.append(("pw-str  uid  ", uid.encode(), realm.encode(), pw.encode()))
    except Exception:                                              # noqa: BLE001
        pass
    return out


def _txid():
    """Fresh transaction id -- never reuse one across requests on a
    connection; some servers key allocation state by it."""
    return os.urandom(12)


def attempt(user, realm_bytes, key, mi_len_in_hdr, send_realm, fp,
            nonce_attr=None):
    """One TLS connection, two requests, fresh txids.

    (nonce_attr, realm_bytes): how to fill REALM/NONCE.  When nonce_attr is
    None we take the NONCE the server just issued on this connection.
    """
    ss = tls()
    tx1 = _txid()
    ss.sendall(stun(0x0003, [], tx1))
    d = ss.recv(4096)
    _mt, at = parse(d)
    nonce = next((v for n, v, _ in at if n == "NONCE"), "")
    realm = next((v for n, v, _ in at if n == "REALM"), "")
    if not nonce:
        ss.close()
        return None, [], "no nonce in %s" % (_mt,)

    attrs = [(0x0006, user)]
    if send_realm:
        rb = realm_bytes if realm_bytes else realm.encode()
        attrs.append((0x0014, rb))
    attrs.append((0x0015, (nonce_attr or nonce).encode()))
    attrs.append((0x0011, bytes([17, 0, 0, 0])))       # requested: UDP
    attrs.append((0x000D, struct.pack("!I", 600)))
    tx2 = _txid()          # distinct txid: do not reuse the probe's

    body = b""
    for at_t, v in attrs:
        pad = (4 - len(v) % 4) % 4
        body += struct.pack("!HH", at_t, len(v)) + v + b"\x00" * pad

    # MESSAGE-INTEGRITY: header length includes it, HMAC covers up to it.
    if mi_len_in_hdr:
        pre = struct.pack("!HHI", 0x0003, len(body) + 24, MAGIC) + tx2 + body
    else:
        pre = struct.pack("!HHI", 0x0003, len(body), MAGIC) + tx2 + body
    mac = hmac.new(key, pre, hashlib.sha1).digest()
    mi = struct.pack("!HH", 0x0008, 20) + mac
    if fp:
        # FINGERPRINT is CRC32 of the message with its own length included
        crc_body = body + mi + struct.pack("!HH", 0x0019, 4) + b"\x00\x00\x00\x00"
        crc = struct.crc32(struct.pack("!HHI", 0x0003, len(crc_body), MAGIC)
                           + tx2 + crc_body) & 0xFFFFFFFF
        mi += struct.pack("!HH", 0x0019, 4) + struct.pack("!I", crc ^ 0x5354554e)

    msg = (struct.pack("!HHI", 0x0003, len(body) + len(mi), MAGIC) + tx2
           + body + mi)
    ss.sendall(msg)
    d = ss.recv(4096)
    ss.close()
    mt, at = parse(d)
    ok = mt == 0x0103
    err = next((v for n, v, _ in at if n == "ERROR-CODE"), "")
    return mt, at, ok, err


def main() -> int:
    detail = "--success-detail" in sys.argv
    print("=== gate: CMD_GET_TURN_SERVER_LIST ===")
    g, exp, pw, uid = gate_account()
    ts = int(exp) if exp.isdigit() else 0
    print("  turn_account.id = %s  -> %s"
          % (exp, ("unix expiry, %d s from now" % (ts - int(time.time())))
             if 10 ** 9 < ts < 2 * 10 ** 9 else "not a timestamp"))
    print("  pw: %d chars base64ish=%s"
          % (len(pw), all(c.isalnum() or c in "+/=" for c in pw)))
    print("  user_id: %s" % uid)
    time.sleep(PACE)

    cands = candidates(exp, pw, uid, "")
    print("\n=== probing credential schemes ===")
    print("  %d keys x {REALM sent, omitted} x {MI-len-in-header, not}\n"
          % len(cands))
    best = None
    tried = 0
    for label, user, realm_b, key in cands:
        for send_realm in (True, False):
            for hdr in (True, False):
                tried += 1
                try:
                    mt, at, ok, err = attempt(
                        user, realm_b, key, hdr, send_realm, False)
                except Exception as e:                            # noqa: BLE001
                    print("  %-34s realm=%-5s hdr=%-5s ERR %s"
                          % (label, send_realm, hdr, e))
                    continue
                mark = "  <== ALLOCATED" if ok else ""
                print("  %-34s realm=%-5s hdr=%-5s method=0x%04x %-20s%s"
                      % (label, send_realm, hdr, mt or 0, str(err)[:20], mark))
                if ok and best is None:
                    best = (label, at)
                    if detail:
                        for n, v, _ in at:
                            print("        %-20s %s" % (n, v))
    print("\n  %d attempts" % tried)
    if best:
        print("SUCCESS: %s" % best[0])
        return 0
    print("no scheme authenticated -- all 401")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
