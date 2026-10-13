#!/usr/bin/env python3
"""stun_session.py -- full bot-side STUN conversation the real game runs
from its game UDP endpoint, mirroring the capture's T1/T3/T4/T6/T7 labels
(captures/match-2026-09-26/*/match_log.txt).

The game, right after session creation, from ONE socket (the port it
advertises in ntl_address_list):
  T1  binding request -> Konami STUN (learn reflexive mapping)
  T3  bare binding    -> OTHER_ADDRESS server(s) 3478 and 3479
  T4  CHANGE_REQUEST (change IP+port)  -> NAT classification
  T6  CHANGE_REQUEST (change port)     -> NAT classification
  T7  BINDING_REQUEST + attr 0x9090 (own user_id) every 5s, whole session

We only ever beat T7 before. The gate cross-checks the nat_type we report
in CMD_SET_GAME_SESSION_CHECK_RES against what Konami STUN observed.

  python stun_session.py            # bind :44000, run sequence, keep beating
"""
import json
import os
import socket
import struct
import sys
import time

WORK = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, WORK)
from p2p_stun import Speaker, attr, p2p_header, parse  # noqa: E402

PORT = int(os.environ.get("PEER_PORT", "44000"))
STUN_HOST = os.environ.get("STUN_HOST", "pesam.stun.service.konami.net")
STUN_PORT = int(os.environ.get("STUN_PORT", "3478"))
INTERVAL = float(os.environ.get("KEEPALIVE_S", "5.0"))
MAGIC = b"\x21\x12\xa4\x42"

ATTR_MAPPED = 0x0001
ATTR_CHANGE = 0x0003
ATTR_OTHER = 0x802C


def breq(attrs=b"", tid=None):
    body = attrs
    return (struct.pack(">HH", 0x0001, len(body)) + MAGIC +
            (tid or os.urandom(12)) + body)


def t7(uid):
    body = attr(0x9090, p2p_header(uid))
    return breq(body)


def parse_reply(buf):
    """-> (tid, {attr_type: bytes})"""
    mtype, tid, attrs = parse(buf)
    return tid, dict(attrs)


def other_addr(attrs):
    """OTHER_ADDRESS (0x802C): family(1)+rsv(1)+port(2)+addr(4)"""
    v = attrs.get(ATTR_OTHER)
    if not v or len(v) < 8:
        return None
    port = struct.unpack(">H", v[2:4])[0]
    ip = socket.inet_ntoa(v[4:8])
    return (ip, port)


def main():
    uids = []
    for fn in ("owner_identity.json", "bot_identity.json"):
        try:
            with open(os.path.join(WORK, fn), encoding="utf-8") as f:
                u = str(json.load(f).get("user_id") or "")
            if u and u not in uids:
                uids.append(u)
        except OSError:
            pass
    sp = Speaker(uids[0], bind=("0.0.0.0", PORT))
    sock = sp.sock
    sock.settimeout(2.0)
    import socket as _s
    primary = _s.getaddrinfo(STUN_HOST, STUN_PORT, _s.AF_INET,
                             _s.SOCK_DGRAM)[0][4]
    print("session bound :%d uids=%s primary=%s" % (PORT, ",".join(uids),
                                                    primary))
    sys.stdout.flush()

    def xact(dest, msg, label):
        try:
            sock.sendto(msg, dest)
        except OSError as e:
            print("  %s send failed: %s" % (label, e))
            return None
        t0 = time.monotonic()
        while time.monotonic() - t0 < 2.0:
            try:
                buf, src = sock.recvfrom(4096)
            except socket.timeout:
                break
            try:
                tid, attrs = parse_reply(buf)
            except ValueError:
                continue
            print("  %-10s -> reply %d bytes from %s (%.2fs) attrs=%s"
                  % (label, len(buf), src, time.monotonic() - t0,
                     ",".join("%04x" % k for k in sorted(attrs))))
            sys.stdout.flush()
            return attrs
        print("  %-10s -> NO REPLY" % label)
        sys.stdout.flush()
        return None

    # T1: binding with RESPONSE-PORT? plain binding to primary
    a1 = xact(primary, breq(), "T1 primary")
    alt = other_addr(a1 or {}) or ("35.76.243.83", 3478)
    print("  OTHER_ADDRESS -> %s:%d" % alt)
    sys.stdout.flush()

    # T3: bare binding to alternate server on both ports
    for port in (3478, 3479):
        xact((alt[0], port), breq(), "T3 alt:%d" % port)

    # T4: CHANGE_REQUEST change IP+port (0x0006)
    xact(primary, breq(attr(ATTR_CHANGE, struct.pack(">I", 0x06))),
         "T4 chgIPPort")
    # T6: CHANGE_REQUEST change port only (0x0002)
    xact(primary, breq(attr(ATTR_CHANGE, struct.pack(">I", 0x02))),
         "T6 chgPort")

    # T7 loop: keepalive both uids every INTERVAL, answer incoming
    print("T7 loop: every %.1fs" % INTERVAL)
    sys.stdout.flush()
    sent = got = 0
    last = 0.0
    while True:
        now = time.monotonic()
        if now - last >= INTERVAL:
            for uid in uids:
                try:
                    sock.sendto(t7(uid), primary)
                    sent += 1
                except OSError as e:
                    print("send failed: %s" % e)
            last = now
        ev = sp.pump(0.2)
        if ev:
            got += 1
            print("ev=%-4s from %s id=%s (sent %d got %d)"
                  % (ev["ev"], ev["src"], ev.get("id"), sent, got))
            sys.stdout.flush()
        sp._pending = None


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
