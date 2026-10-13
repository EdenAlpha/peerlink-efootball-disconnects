#!/usr/bin/env python3
"""probe_cmds.py -- fast single-shot probes of gate commands chain3 never sends.

Findings so far: the wall is abnormal=DISCONN_HB stamped ~2 s after
START_GAME.  The LATENCY registry's CONNECT phase has no gate commands,
but the binary carries relay-quality vocabulary the bot has never used:

  ERR_GAMERELAY_QUALITY_NOT_MEASURE   (ELobbyCreatejoinRoomError)
  ERR_GAMERELAY_NOTENOUGH
  ERR_FAILED_CONNECT_RELAY_TIMEOUT
  CMD_SET_GAMERELAY_QUALITY
  CMD_GET_GAMERELAY_QUALITYCHECK_LIST
  CMD_SEND_SESSION_ID / CMD_SEND_SESSION_FAILED_NOTICE

We also report gamerelay_measure_result="MEASUREING" forever -- a
measurement that never completes.  These probes find out which of these
the gate accepts and what each reply carries.

  python probe_cmds.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from room1 import Gate, load_capture, login, describe          # noqa: E402
from room2 import BOT_FILE, login_bot                          # noqa: E402
from chain3 import (create_room, game_session, match_ready,    # noqa: E402
                    entry_side)


def sh(r):
    keys = ",".join(k for k in sorted(r) if k not in ("result", "msgid", "rqid"))
    body = {k: v for k, v in r.items()
            if k not in ("result", "msgid", "rqid", "show_info",
                         "maintenance_end_time")}
    return "%s keys=[%s]%s" % (
        r.get("result"), keys,
        ("  " + json.dumps(body, ensure_ascii=False,
                           default=str)[:1800]) if body else "")


def main() -> int:
    reqs, _ = load_capture()
    owner = Gate()
    ok, _ = login(owner, reqs)
    print("owner login ->", ok)
    if not ok:
        return 1

    botg = Gate()
    with open(BOT_FILE, encoding="utf-8") as fh:
        bot = json.load(fh)
    okb, _rb = login_bot(botg, reqs, bot)
    print("bot login   ->", okb)

    o = create_room(owner)
    rid = ((o.get("room_id") or {}).get("id")) if o.get("result") == "NOERR" else None
    print("create room -> %s rid=%s" % (o.get("result"), rid))
    if not rid:
        print(" ", describe(o))
        return 1

    for side, leader, g in (("HOME", True, owner), ("AWAY", False, botg)):
        r = g.send(entry_side(g, rid, side, leader))
        print("entry_side  [%s] -> %s" % (side, r.get("result")))

    for tag, g in (("owner", owner), ("bot  ", botg)):
        r = g.send(match_ready(g, rid, "owner" if g is owner else "bot"))
        print("match_ready [%s] -> %s" % (tag, r.get("result")))

    gs = owner.send(game_session(owner, rid))
    game_id = None
    for cand in ("game_id", "id"):
        v = (gs.get(cand) or {}).get("id") if isinstance(gs.get(cand), dict) \
            else gs.get(cand)
        if v:
            game_id = v
            break
    print("game_session -> %s game_id=%s" % (gs.get("result"), game_id))

    # ---- relay quality family + session reports, several body shapes ----
    probes = [
        ("CMD_GET_GAMERELAY_QUALITYCHECK_LIST", {}),
        ("CMD_GET_GAMERELAY_QUALITYCHECK_LIST", {"room_id": {"id": rid}}),
        ("CMD_SET_GAMERELAY_QUALITY", {"gamerelay_measure_result": "MEASUREING"}),
        ("CMD_SET_GAMERELAY_QUALITY", {"room_id": {"id": rid},
                                       "gamerelay_measure_result": "MEASUREING"}),
        ("CMD_SEND_SESSION_ID", {}),
        ("CMD_SEND_SESSION_ID", {"game_id": game_id}),
        ("CMD_SEND_SESSION_FAILED_NOTICE", {}),
        ("CMD_SEND_SESSION_FAILED_NOTICE", {"game_id": game_id}),
        ("CMD_SET_LOCAL_GAMERELAY_LIST", {"gamerelay_list": []}),
    ]
    if game_id:
        probes.append(("CMD_SET_GAMERELAY_QUALITY",
                       {"game_id": game_id,
                        "gamerelay_measure_result": "MEASUREING"}))
        probes.append(("CMD_SEND_SESSION_ID",
                       {"game_id": game_id,
                        "platform_session_id_info": {"ps_session_id": "",
                                                     "xb_session_id": ""}}))

    for cmd, body in probes:
        m = owner.envelope(cmd)
        m.update({k: v for k, v in body.items() if v is not None})
        r = owner.send(m)
        print("%-38s %-22s -> %s" % (
            cmd, json.dumps(body, default=str)[:22], sh(r)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
