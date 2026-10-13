#!/usr/bin/env python3
"""probe_turnlist.py -- pull the live TURN/DTLS rendezvous list for P2P mode.

CMD_GET_TURN_SERVER_LIST takes the body

    {"turn_account_param": "", "turn_time_limit": 0}

(verified schema, ROOM-SCHEMA.md) and answers NOERR with

    turn_server_list[i] = {zone, address, port, tls_port}
    turn_account       = {id, password, origin, server_certificate}

This is the P2P-mode DTLS endpoint source: in P2P the session is NOT played
over an assigned gamerelay (that is SC mode), it is played over the TURN/
DTLS rendezvous from here.  chain3 has never sent this command, which is why
it has no DTLS endpoint to dial.

Credentials in turn_account are session-bound and short-lived -- printed as
shape only, never raw.

  python probe_turnlist.py
"""
import json
import socket
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import Gate, load_capture, login, PACE, describe   # noqa: E402
from room_info_shape import SENSITIVE, shape                  # noqa: E402

SENSITIVE.update({"id", "serial"})
HIDE = ("password", "server_certificate", "id")


def show(o, limit=1200) -> str:
    return json.dumps(shape(o), ensure_ascii=False, default=str)[:limit]


def redact(o):
    if isinstance(o, dict):
        return {k: ("<redacted len=%d>" % len(v) if k in HIDE and
                    isinstance(v, (str, bytes)) else redact(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [redact(v) for v in o]
    return o


def main() -> int:
    reqs, _ = load_capture()
    g = Gate()
    ok, r = login(g, reqs)
    print("login -> %s" % (r.get("result") if ok else describe(r)))
    if not ok:
        return 1
    time.sleep(PACE)

    m = g.envelope("CMD_GET_TURN_SERVER_LIST")
    m["turn_account_param"] = ""
    m["turn_time_limit"] = 0
    t0 = time.time()
    tr = g.send(m, timeout=15)
    print("GET_TURN_SERVER_LIST -> %s  (%.1fs)"
          % (tr.get("result"), time.time() - t0))
    keys = ",".join(k for k in sorted(tr)
                    if k not in ("result", "msgid", "rqid"))
    print("  keys: %s" % keys)
    print("  body: %s" % show(redact(tr), 2500))

    tsl = tr.get("turn_server_list") or []
    if not tsl:
        print("  (no turn_server_list -- nothing to dial)")
        return 0

    print("\n=== %d TURN/DTLS endpoints ===" % len(tsl))
    cands = []
    for e in tsl:
        if not isinstance(e, dict):
            print("   %r" % (e,))
            continue
        z, a = e.get("zone"), e.get("address")
        p, tp = e.get("port"), e.get("tls_port")
        print("   zone=%-18s address=%-46s port=%-6s tls_port=%s"
              % (z, a, p, tp))
        for port in (p, tp):
            if isinstance(port, int) and a:
                cands.append((a, port))

    print("\n=== reachability (DTLS ClientHello over UDP) ===")
    for host, port in cands:
        info = probe(host, port)
        print("   %-46s %-6s %s" % (host, port, info))
    return 0


def probe(host, port, timeout=2.0):
    CH = bytes.fromhex(
        "010000aa00000000000000aafefd2ce000aae7c834630cfa8c0d48d28b2e1a4"
        "a5560a8b8750fbb4255563fd68db200000032c02cc030009fc02bc02f009ec02"
        "4c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035")
    hs = bytes([1]) + len(CH).to_bytes(3, "big") + b"\x00\x00\x00\x00\x00\x00"
    rec = (bytes([22]) + b"\xfe\xff" + b"\x00\x00" + (0).to_bytes(6, "big")
           + len(hs + CH).to_bytes(2, "big") + hs + CH)
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET,
                                socket.SOCK_DGRAM)[0][4][0]
    except OSError as e:
        return "dns %s" % e
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t0 = time.time()
        s.sendto(rec, (ip, port))
        d, _ = s.recvfrom(2048)
        kind = "appdata" if d[:1] == b"\x17" else (
            "handshake" if d[:1] == b"\x16" else "other")
        hs_t = d[13] if len(d) > 13 and d[:1] == b"\x16" else -1
        return "ANSWERED %s hs_type=%d %dms" % (kind, hs_t,
                                                int((time.time() - t0) * 1000))
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return "err %s" % e
    finally:
        s.close()


if __name__ == "__main__":
    raise SystemExit(main())
