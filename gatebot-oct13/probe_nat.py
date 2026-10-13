#!/usr/bin/env python3
"""probe_nat.py -- what NAT type makes the server assign a relay?

CMD_GET_GAME_SESSION answers game_sycom="P2P" + gamerelay=NotImplement for
both our bots, both advertising nat_type=1.  A P2P room has no relay, so
the LATENCY_MODE_CONNECT phase has nothing to connect to and the server
stamps abnormal=DISCONN_HB ~2 s after START_GAME.

The relay fleet itself IS reachable (probe_quality.py got a 9.9 ms UDP
answer from us-east5), so the missing piece is getting the server to hand
one out.  Real matchmaking assigns a relay when a peer sits behind a
restrictive NAT.  This varies nat_type in CMD_SET_ROOM_MATCH_READY, in a
FRESH room each time (match_ready is one-shot -> ERR_ALREADY_READY), with
the bot properly invited/joined/seated, then re-reads CMD_GET_GAME_SESSION.

  python probe_nat.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from room1 import Gate, load_capture, login                      # noqa: E402
from room2 import BOT_FILE, join_body, login_bot, NET            # noqa: E402
from chain3 import (create_room, entry_side, game_session,       # noqa: E402
                    getrequested, num_users, sendreq, match_ready)


def ready_with(g, rid, tag, nat):
    """CMD_SET_ROOM_MATCH_READY advertising a chosen nat_type."""
    net = dict(NET)
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "peer_endpoint.json" if tag == "owner"
                               else "peer_endpoint_bot.json"),
                  encoding="utf-8") as f:
            ep = json.load(f)
        net.update({"host_address": ep["ip"], "host_port": ep["port"],
                    "reflexive_address": ep["ip"], "reflexive_port": ep["port"]})
    except (OSError, KeyError, ValueError, TypeError):
        pass
    net["nat_type"] = nat
    m = g.envelope("CMD_SET_ROOM_MATCH_READY")
    m.update({"room_id": {"id": rid}, "is_single_matching": "YES",
              "gamerelay_measure_result": "MEASUREING",
              "address_ipv4": net, "address_ipv6": dict(NET)})
    return g.send(m)


def main() -> int:
    reqs = load_capture()[0]
    owner = Gate()
    if not login(owner, reqs)[0]:
        print("owner login failed")
        return 1
    botg = Gate()
    with open(BOT_FILE, encoding="utf-8") as fh:
        bot = json.load(fh)
    if not login_bot(botg, reqs, bot)[0]:
        print("bot login failed")
        return 1

    for nat in (1, 2, 3, 4):
        # -- fresh room, both sides properly seated --
        o = create_room(owner)
        rid = ((o.get("room_id") or {}).get("id")) \
            if o.get("result") == "NOERR" else None
        if not rid:
            print("nat=%d create room failed: %s" % (nat, o.get("result")))
            continue
        if sendreq(botg, 0, rid).get("result") != "NOERR":
            print("nat=%d bot sendreq failed" % nat)
            continue
        if sendreq(owner, botg.uid, rid).get("result") != "NOERR":
            print("nat=%d owner invite failed" % nat)
            continue
        if getrequested(botg, owner.uid).get("result") != "NOERR":
            print("nat=%d bot getreq failed" % nat)
            continue
        jb = join_body(botg, rid)
        jb["mode"] = "CUSTOM"
        if botg.send(jb).get("result") != "NOERR":
            print("nat=%d bot join failed" % nat)
            continue
        seated = num_users(owner, rid)
        for side, leader, g in (("HOME", True, owner), ("AWAY", False, botg)):
            g.send(entry_side(g, rid, side, leader))

        ro = ready_with(owner, rid, "owner", nat)
        rb = ready_with(botg, rid, "bot", nat)
        gs = owner.send(game_session(owner, rid))
        gr = gs.get("gamerelay") or {}
        print("nat_type=%d seated=%s ready[own]=%-16s ready[bot]=%-16s "
              "sycom=%-4s gamerelay=%s:%s" % (
                  nat, seated, ro.get("result"), rb.get("result"),
                  gs.get("game_sycom"), gr.get("ip_addr"), gr.get("port")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
