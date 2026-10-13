#!/usr/bin/env python3
"""stun_keepalive.py -- bot-side T7 Signal keepalive to Konami's STUN server.

The real game sends an RP_ (method 0x20B, attr 0x9090 = RP_P2P_HEADER with
its own user_id) request to pesam.stun.service.konami.net:3478 every ~5 s
for the whole session (403x in the match capture, STUN[T7:Signal] lines).
The gate can observe that mapping via Konami STUN infra; our bots never
speak it -> candidate DISCONN_HB liveness signal.

  python stun_keepalive.py                 # bind :44000, beat every 5s
  PEER_PORT=44001 python stun_keepalive.py
"""
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p2p_stun import Speaker, attr, p2p_header  # noqa: E402
import struct

WORK = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PEER_PORT", "44000"))
STUN_HOST = os.environ.get("STUN_HOST", "pesam.stun.service.konami.net")
STUN_PORT = int(os.environ.get("STUN_PORT", "3478"))
INTERVAL = float(os.environ.get("KEEPALIVE_S", "5.0"))

MAGIC = b"\x21\x12\xa4\x42"


def t7(uid: str) -> bytes:
    """T7 Signal = STUN BINDING_REQUEST carrying attr 0x9090 (verified:
    both Konami STUN IPs answer this form; method 0x080B+0x9090 is not
    answered -- that form is the peer-punch conversation only)."""
    body = attr(0x9090, p2p_header(uid))
    return struct.pack(">HH", 0x0001, len(body)) + MAGIC + os.urandom(12) + body


def stun_mapped(sock, uid, dest, timeout=2.0):
    """Send the T7 form (known-answered) from THIS socket and parse the
    MAPPED-ADDRESS (0x0001) out of the Binding Response -- i.e. the exact
    ip:port Konami STUN saw as our source.  Run #30 advertised a stale
    3.80.79.52:52010 while the beats actually left from the current egress;
    the server saw a live keepalive but could not correlate it to the match
    -> still DISCONN_HB.  Returns (ip, port) or None."""
    req = t7(uid)
    txid = req[8:20]
    try:
        sock.sendto(req, dest)
    except OSError:
        return None
    old = sock.gettimeout()
    sock.settimeout(timeout)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(2048)
            except (socket.error, socket.timeout):
                continue
            if len(data) < 20 or data[4:8] != MAGIC or data[8:20] != txid:
                continue
            alen = struct.unpack(">H", data[2:4])[0]
            off, end = 20, min(20 + alen, len(data))
            while off + 4 <= end:
                atype, rlen = struct.unpack(">HH", data[off:off + 4])
                aval = data[off + 4:off + 4 + rlen]
                if atype == 0x0001 and len(aval) >= 8:      # MAPPED-ADDRESS
                    port = struct.unpack(">H", aval[2:4])[0]
                    return (socket.inet_ntoa(aval[4:8]), port)
                off += 4 + rlen + ((4 - (rlen % 4)) % 4)
    finally:
        sock.settimeout(old)
    return None


def main() -> int:
    # both identities beat in the real match (each phone carries its own
    # user_id in the RP_P2P_HEADER); we previously beat only the bot uid
    # and the server stamped the OWNER side DISCONN_HB.
    uids = []
    with open(os.path.join(WORK, "bot_identity.json"), encoding="utf-8") as f:
        uids.append(str(json.load(f)["user_id"]))
    for cand in ("owner_identity.json",):
        try:
            with open(os.path.join(WORK, cand), encoding="utf-8") as f:
                u = str(json.load(f).get("user_id") or "")
            if u and u not in uids:
                uids.append(u)
        except OSError:
            pass
    import socket
    sp = Speaker(uids[0], bind=("0.0.0.0", PORT))
    dest = (STUN_HOST, STUN_PORT)
    print("keepalive bound :%d uids=%s -> %s:%d every %.1fs"
          % (PORT, ",".join(uids), STUN_HOST, STUN_PORT, INTERVAL))
    sys.stdout.flush()

    # --- startup: capture the TRUE reflexive (what Konami STUN sees as our
    #     source) and publish it so chain3 advertises an endpoint that MATCHES
    #     this keepalive's beats.  Bind-time STUN fixes the correlation that
    #     run #30 broke with a stale 3.80.79.52:52010 guess.
    try:
        dest = socket.getaddrinfo(STUN_HOST, STUN_PORT,
                                  socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except OSError:
        pass
    mapped = stun_mapped(sp.sock, uids[0], dest)
    epfile = "peer_endpoint.json" if PORT == 44000 else "peer_endpoint_bot.json"
    if mapped:
        print("STUN mapped  :%d -> %s:%d (advertising this reflexive)"
              % (PORT, mapped[0], mapped[1]))
        with open(os.path.join(WORK, epfile), "w", encoding="utf-8") as f:
            json.dump({"ip": mapped[0], "port": mapped[1],
                       "local_port": PORT}, f)
    else:
        print("STUN mapped  :%d -> NONE (keeping existing %s)"
              % (PORT, epfile))
    sys.stdout.flush()

    sent = got = 0
    last_send = 0.0
    while True:
        now = time.monotonic()
        if now - last_send >= INTERVAL:
            try:
                dest = socket.getaddrinfo(STUN_HOST, STUN_PORT,
                                          socket.AF_INET,
                                          socket.SOCK_DGRAM)[0][4]
            except OSError:
                pass                      # keep last good dest
            for uid in uids:
                msg = t7(uid)
                try:
                    sp.sock.sendto(msg, dest)
                    sent += 1
                except OSError as e:
                    print("send failed: %s" % e)
            last_send = now
        ev = sp.pump(0.2)
        if ev:
            got += 1
            print("ev=%-4s from %s id=%s (sent %d got %d)"
                  % (ev["ev"], ev["src"], ev.get("id"), sent, got))
            sys.stdout.flush()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
