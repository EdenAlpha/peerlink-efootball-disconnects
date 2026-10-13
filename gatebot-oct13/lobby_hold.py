#!/usr/bin/env python3
"""lobby_hold.py -- create a lobby 1v1 room (mode=CUSTOM, kind=SINGLE) and
hold the session so a REAL phone can find and join it by number.

STRIKE_ARENA rooms (the old chain's CFG) never appear in the phone's room
list -- that is why the number handed over earlier was unusable.  This is
the deliverable shape: human phone + PeerLink bot as the two sides.

  python lobby_hold.py            create, print room number, hold + watch
"""
import json
import os
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import chain3 as c3                                          # noqa: E402
from room1 import (CFG, PACE, Gate, create_room, describe,  # noqa: E402
                   login, load_capture, relay_quality)
from room_info_shape import SENSITIVE, shape                 # noqa: E402

SENSITIVE.update({"user_id"})

CMD_FILE = r"C:\Users\Administrator\Documents\Default Project\work\lobby_cmd.txt"


def run_cmd(g: Gate, rid: int, line: str) -> bool:
    """execute one lobby command; returns False to stop the holder."""
    parts = line.split()
    op = parts[0].lower() if parts else ""
    if op == "squad":
        sq = g.send(c3.user_squad(g, g.uid))
        tid = c3.find_key(sq, "base_team_id")
        n = len(((sq.get("squad_data") or {}).get("player_list")) or [])
        print("[cmd] squad -> %s players=%d team_id_present=%s"
              % (sq.get("result"), n, tid is not None), flush=True)
    elif op == "side":
        s = "HOME" if parts[1].upper().startswith("H") else "AWAY"
        r = g.send(c3.entry_side(g, rid, s, s == "HOME"))
        print("[cmd] side %s -> %s" % (s, r.get("result")), flush=True)
    elif op == "ready":
        r = g.send(c3.match_ready(g, rid))
        print("[cmd] ready -> %s" % r.get("result"), flush=True)
    elif op == "session":
        # the server-mediated introduction: both sides' addresses are
        # in the session.  Extract the OPPONENT's (non-ours) and hand
        # it to udp_punch.py so the bot punches outbound (stateful
        # firewalls only open for reply traffic -- this is the piece
        # real clients do that we were missing).
        r = g.send(c3.game_session(g, rid))
        print("[cmd] session -> %s" % r.get("result"), flush=True)
        ours = set()
        try:
            with open(c3.EP_FILE, encoding="utf-8") as fh:
                ours.add(json.load(fh).get("ip"))
        except (OSError, ValueError, TypeError):
            pass
        ours |= {"", None, "NotImplement"}
        found = []

        def walk(v):
            if isinstance(v, dict):
                for ak, pk in (("host_address", "host_port"),
                               ("reflexive_address", "reflexive_port")):
                    a, p = v.get(ak), v.get(pk)
                    if isinstance(a, str) and a and a not in ours:
                        try:
                            found.append((a, int(p)))
                        except (TypeError, ValueError):
                            pass
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)

        walk(r)
        uniq = sorted(set(found))
        # raw relay spec (not credentials -- the server hands the same
        # values to both clients; we need the unmasked connection spec)
        gr = r.get("gamerelay")
        if isinstance(gr, dict):
            print("  RAW gamerelay: name=%r region=%r ip=%r port=%r"
                  % (gr.get("name"), gr.get("region"),
                     gr.get("ip_addr"), gr.get("port")), flush=True)
        ntl = r.get("ntl_address_list")
        if ntl:
            print("  RAW ntl entries: %s"
                  % json.dumps(shape(ntl), ensure_ascii=False,
                               default=str)[:900], flush=True)
        print("  session shape: %s"
              % json.dumps(shape(r), ensure_ascii=False,
                           default=str)[:1200], flush=True)
        if uniq:
            tgt = uniq[0]
            tf = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "peer_target.json")
            with open(tf, "w", encoding="utf-8") as fh:
                json.dump({"ip": tgt[0], "port": tgt[1],
                           "seen": time.time()}, fh)
            print("  peer target -> %s:%d (punching starts)"
                  % tgt, flush=True)
        else:
            print("  no opponent address in session yet", flush=True)
    elif op == "state":
        print("[cmd] state requested -- next poll prints", flush=True)
    elif op == "drop":
        print("[cmd] drop -> stopping holder", flush=True)
        return False
    else:
        print("[cmd] unknown command %r" % line, flush=True)
    return True


def main() -> int:
    CFG["mode"] = "CUSTOM"
    CFG["kind"] = "SINGLE"

    reqs = load_capture()[0]
    g = Gate()
    if "--bot" in sys.argv:
        import json as _json
        from room2 import BOT_FILE, login_bot
        bot = _json.load(open(BOT_FILE, encoding="utf-8"))
        ok, r = login_bot(g, reqs, bot)
        print("bot login    -> %s" % (r.get("result") if ok else describe(r)),
              flush=True)
    else:
        ok, r = login(g, reqs)
        print("login        -> %s" % (r.get("result") if ok else describe(r)),
              flush=True)
    if not ok:
        return 1
    time.sleep(PACE)

    q = relay_quality(g, reqs)
    print("relay quality-> %s" % q.get("result"), flush=True)
    time.sleep(PACE)

    o = create_room(g)
    print("create room  -> %s" % o.get("result"), flush=True)
    if o.get("result") != "NOERR":
        print("  %s" % describe(o), flush=True)
        return 1
    rid = (o.get("room_id") or {}).get("id")
    print("ROOM NUMBER  -> %s" % rid, flush=True)

    last = None
    last_go = None
    t0 = time.time()
    auto_done = False
    while True:
        time.sleep(5.0)
        if os.path.exists(CMD_FILE):
            try:
                with open(CMD_FILE, encoding="utf-8") as fh:
                    line = fh.read().strip()
            except Exception:                              # noqa: BLE001
                line = ""
            os.replace(CMD_FILE, CMD_FILE + ".done")
            if line and not run_cmd(g, rid, line):
                return 0
        try:
            m = g.envelope("CMD_GET_ROOM_INFO")
            m.update({"mode": "CUSTOM", "id": 0, "room_id": {"id": rid},
                      "event_id": 0, "user_compe_id": 0,
                      "is_room_search": "NO"})
            ri = g.send(m)
        except Exception as e:                             # noqa: BLE001
            # transient network reset (WARP/Tailscale flap) -- the
            # session survives; do NOT die and cost the user a relaunch
            print("[%.0fs] poll reset: %s (holder still up)"
                  % (time.time() - t0, e), flush=True)
            continue
        if ri.get("result") != "NOERR":
            print("[%.0fs] room_info -> %s (holder still up)"
                  % (time.time() - t0, ri.get("result")), flush=True)
            continue
        info = ri.get("room_info") or {}
        # autopilot: the moment a real user sits, seat + ready the bot.
        # The user must NEVER wait on a chat prompt (waiting kills their
        # game -- Android relaunches on every app switch).
        nu = c3.find_key(info, "num_users")
        try:
            nu = int(nu)
        except (TypeError, ValueError):
            nu = 1
        if nu >= 2 and not auto_done:
            print("[auto] user in room -- seating the bot (no prompts "
                  "needed)", flush=True)
            for op in ("squad", "side H", "ready"):
                if not run_cmd(g, rid, op):
                    return 0
                time.sleep(1.0)
            auto_done = True
        elif nu < 2 and auto_done:
            print("[auto] user left -- will re-seat on rejoin", flush=True)
            auto_done = False
        cur = json.dumps(shape(info), ensure_ascii=False, default=str,
                         sort_keys=True)
        changed = cur != last
        go = c3.find_key(info, "is_go_match")
        # match starting -> pull the introduction and punch (automatic;
        # the user must never wait on a chat prompt)
        if go == "YES" and (last_go != "YES" or changed):
            run_cmd(g, rid, "session")
        last_go = go
        if changed:
            print("[%.0fs] room state changed:" % (time.time() - t0),
                  flush=True)
            print("  %s" % cur[:1500], flush=True)
            last = cur
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
