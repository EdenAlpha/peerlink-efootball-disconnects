#!/usr/bin/env python3
"""probe_turn_auth4.py -- find the REALM the server is asking for.

probe_turn_auth3.py got the server to explain itself:

    realm=''         -> [4001] Unauthorized        (realm check passed, MI failed)
    realm='anything' -> [4037] Allocation mismatch:
                         "wrong credentials: the realm value is incorrect"

So there IS a configured non-empty realm, the challenge just advertises it
as zero-length, and we have never sent the value it wants.  Candidates are
not guesses about Konami's DNS -- they are the strings our own
CMD_GET_TURN_SERVER_LIST reply already carries: each turn_server_list entry's
zone, the turn_account origin, the SNI, and the TURN host's own name.

With the realm pinned, the key collapses to the standard MD5(user:realm:pw).

  python probe_turn_auth4.py
"""
import hashlib
import hmac
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import Gate, load_capture, login, PACE, describe       # noqa: E402

TURN_HOST, TURN_PORT, SNI = "130.211.8.132", 443, "pes20.turn.konami.com"
MAGIC = 0x2112A442
LIMIT = 3600

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
            val = "%dB" % len(v)
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


def gate():
    """-> (id, pw, user_id, raw turn list reply)"""
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
    return (str(acc.get("id", "")), str(acc.get("pw", "")),
            str(g.uid), tr)


def attempt(user, pw, realm):
    """One connection: nonce from THIS connection, then a signed Allocate."""
    ss = tls()
    try:
        ss.sendall(struct.pack("!HHI", 0x0003, 0, MAGIC) + txid())
        d = ss.recv(4096)
        _mt, at = parse(d)
        nonce = next((raw for n, _v, raw in at if n == "NONCE"), b"")
        if not nonce:
            return None, []
        key = hashlib.md5(("%s:%s:%s" % (user, realm, pw)).encode()).digest()
        attrs = [(0x0006, user.encode()),
                 (0x0014, realm.encode()),
                 (0x0015, nonce),
                 (0x0011, bytes([17, 0, 0, 0])),
                 (0x000D, struct.pack("!I", 600))]
        ss.sendall(build(0x0003, attrs, key, txid()))
        d = ss.recv(4096)
    finally:
        try:
            ss.close()
        except Exception:                                        # noqa: BLE001
            pass
    return parse(d)


def realms_from(tr):
    """Every realm-shaped string our own reply carries, plus the obvious
    DNS forms of the endpoint it names."""
    out = []

    def add(s, why):
        if isinstance(s, str) and s and s not in [x[0] for x in out]:
            out.append((s, why))

    acc = tr.get("turn_account") or {}
    org = str(acc.get("origin") or "")
    if org:
        add(org, "origin raw")
        p = urllib.parse.urlparse(org)
        if p.hostname:
            add(p.hostname, "origin host")
            add("%s:%s" % (p.hostname, p.port or ""), "origin host:port")
    for e in (tr.get("turn_server_list") or []):
        if not isinstance(e, dict):
            continue
        add(str(e.get("zone") or ""), "zone")
        add(str(e.get("address") or ""), "entry address")
    add(SNI, "SNI")
    add("turn.konami.com", "turn.konami.com")
    add("konami.com", "konami.com")
    add(TURN_HOST, "TURN ip")
    try:
        add(socket.gethostbyaddr(TURN_HOST)[0], "rDNS of TURN host")
    except OSError:
        pass
    add("", "empty (baseline)")
    return out


def main() -> int:
    print("=== gate: CMD_GET_TURN_SERVER_LIST (turn_time_limit=%d) ===" % LIMIT)
    exp, pw, uid, tr = gate()
    ts = int(exp) if exp.isdigit() else 0
    print("  turn_account.id = %s  expiry in %ds   user_id = %s"
          % (exp, ts - int(time.time()), uid))
    print("  origin          = %s" % (tr.get("turn_account") or {}).get("origin"))
    for e in (tr.get("turn_server_list") or []):
        if isinstance(e, dict):
            print("  entry           zone=%r address=%s port=%s tls_port=%s"
                  % (e.get("zone"), e.get("address"), e.get("port"),
                     e.get("tls_port")))
    time.sleep(PACE)

    cands = realms_from(tr)
    print("\n=== %d realm candidates x 2 usernames ===" % len(cands))
    users = [(exp, "id=expiry"), ("%s:%s" % (exp, uid), "expiry:uid")]
    hits, census, shown = [], {}, 0
    for user, ulab in users:
        for realm, why in cands:
            lbl = "%-10s realm=%-46r [%s]" % (ulab, realm, why)
            try:
                mt, at = attempt(user, pw, realm)
            except Exception as e:                                # noqa: BLE001
                print("  %-70s ERR %s" % (lbl[:70], e))
                continue
            if mt == 0x0103:
                print("  <<< ALLOCATED  user=%s realm=%r" % (ulab, realm))
                for n, v, _ in at:
                    print("        %-22s %s" % (n, v))
                hits.append((user, realm, at))
                continue
            e = next((v for n, v, _ in at if n == "ERROR-CODE"),
                     "no reply (method=%s)" % (mt,))
            census[e] = census.get(e, 0) + 1
            if "realm value is incorrect" not in e:
                print("  %-70s %s" % (lbl[:70], e))
                shown += 1

    print("\n=== census (%d combos) ===" % (len(cands) * len(users)))
    for k, v in sorted(census.items(), key=lambda x: -x[1]):
        print("  %-60s %d" % (k[:60], v))
    if shown == 0 and not hits:
        print("\n  every candidate still -> 'realm value is incorrect':\n"
              "  the realm is not in the turn reply; it must be read\n"
              "  from turn_account.server_certificate or the binary.")
    print("\nRESULT: %s" % ("ALLOCATED" if hits else "no realm accepted"))
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
