#!/usr/bin/env python3
"""sgr_read.py -- read the verdict of the last chain3 run (read-only).

The full-chain stdout was truncated before its tail (goals / SET / verdict),
so this re-reads what matters straight from the server:

  room -> CMD_GET_GAME_ID -> CMD_CHECK_GAME_RESULT -> CMD_GET_GAME_RESULT
         (owner + bot)

Usage: python sgr_read.py --live [room_id]
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import chain3 as c3                      # noqa: E402
from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room2 import BOT_FILE, login_bot    # noqa: E402
from room_info_shape import shape        # noqa: E402


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live [room_id]")
        return 0
    rid = None
    if "--live" in sys.argv:
        idx = sys.argv.index("--live")
        if len(sys.argv) > idx + 1 and sys.argv[idx + 1].isdigit():
            rid = int(sys.argv[idx + 1])
    if rid is None:
        rid = 14846692           # room of the run whose tail was truncated

    reqs = load_capture()[0]
    try:
        with open(BOT_FILE, encoding="utf-8") as fh:
            bot = json.load(fh)
    except Exception:                                  # noqa: BLE001
        bot = {}

    owner = Gate()
    ok, r = login(owner, reqs)
    print("owner login  -> %s" % (r.get("result") if ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1
    time.sleep(PACE)

    botg = Gate()
    okb, rb = login_bot(botg, reqs, bot)
    print("bot login    -> %s" % (rb.get("result") if okb else "NOERR"))
    if not okb:
        print("  %s" % describe(rb))
        return 1
    time.sleep(PACE)

    # -- room -> game_id --------------------------------------------------
    ri = c3.room_state(owner, rid)
    print("room         -> gamephase=%s go_match=%s"
          % (ri.get("gamephase"), ri.get("is_go_match")))
    game_id = c3.get_game_id(owner, rid)
    if game_id is None:
        print("game_id not found in room -- cannot read verdict")
        return 1
    print("game_id      -> yes (%s)" % type(game_id).__name__)
    time.sleep(PACE)

    # -- verdict ----------------------------------------------------------
    m = owner.envelope("CMD_CHECK_GAME_RESULT")
    m["game_id"] = game_id
    c = owner.send(m)
    print("check_result -> %s (%s)" % (c.get("result"), c.get("errcode")))
    print("  %s" % json.dumps(shape(c.get("game_end_result")),
                              ensure_ascii=False, default=str)[:2500])
    time.sleep(PACE)

    for tag, g in (("owner", owner), ("bot  ", botg)):
        m = g.envelope("CMD_GET_GAME_RESULT")
        m["game_id"] = game_id
        r = g.send(m)
        mr = r.get("match_result") or {}
        slim = {k: v for k, v in mr.items()
                if k in ("score", "home", "away", "gameend_reason",
                         "abnormalend_reason", "match_stat_side_info_list",
                         "myteam_player_list")}
        print("get_result [%s] -> %s get_match_result=%s"
              % (tag, r.get("result"), r.get("get_match_result")))
        if slim:
            print("  %s" % json.dumps(shape(slim), ensure_ascii=False,
                                      default=str)[:1400])
        time.sleep(PACE)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
