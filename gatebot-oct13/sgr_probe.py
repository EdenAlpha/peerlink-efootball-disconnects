#!/usr/bin/env python3
"""sgr_probe.py -- fast CMD_SET_GAME_RESULT body-variant probe.

The 6.5-min chain proved every upstream step NOERR while SET alone keeps
answering GKZX- (ERR_INVALIDARG), and the full response names no field.
If the server validates body shape before game state, body variants can be
fired at ~1.2 s pace against a remembered game_id and the FIRST response
that is not GKZX- marks a passing shape.

Controls pin the validation order:
  CHECK(game_id=0)      -> what "game not found" even looks like
  SET(bogus game_id)    -> if it differs from GKZX-, state is checked first

Usage: python sgr_probe.py --live
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

import chain3 as c3                      # noqa: E402
from room1 import Gate, load_capture, login, relay_quality, PACE  # noqa: E402
from room2 import BOT_FILE, login_bot    # noqa: E402
from room_info_shape import shape        # noqa: E402

# last live game (chain3 run 2026-10-10); not a credential
LAST_GAME = 261000124539290303


def brief(r: dict) -> str:
    return "%s (%s)" % (r.get("result"), r.get("errcode"))


def fire(g: Gate, req: dict, tag: str, full_ok: bool = False) -> str:
    m = g.envelope("CMD_SET_GAME_RESULT")
    m.update(req)
    r = g.send(m)
    line = "%-28s -> %s" % (tag, brief(r))
    # anything that is NOT the standing GKZX wall is interesting: print it
    if r.get("errcode") != "GKZX-" or full_ok:
        line += "\n    %s" % json.dumps(shape(r), ensure_ascii=False,
                                        default=str)[:1500]
    print(line)
    time.sleep(1.2)
    return r.get("errcode") or ""


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0
    reqs = load_capture()[0]
    try:
        with open(BOT_FILE, encoding="utf-8") as fh:
            bot = json.load(fh)
    except Exception:                                  # noqa: BLE001
        bot = {}

    owner = Gate()
    ok, r = login(owner, reqs)
    print("owner login  -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        return 1
    time.sleep(PACE)
    q = relay_quality(owner, reqs)
    print("owner quality-> %s" % q.get("result"))
    if q.get("result") != "NOERR":
        return 1
    time.sleep(PACE)

    botg = Gate()
    okb, rb = login_bot(botg, reqs, bot)
    print("bot login    -> %s" % (rb.get("result") if not okb else "NOERR"))
    if not okb:
        return 1
    time.sleep(PACE)

    # realistic entries from the owner's squad (fall back to synthetic ids)
    try:
        sq = owner.send(c3.user_squad(owner, owner.uid))
        mine = c3.squad_list(sq)
        print("squad fetch  -> %s players=%d"
              % (sq.get("result"), len(mine)))
    except Exception:                                  # noqa: BLE001
        mine = []
    if not mine:
        mine = [{"gameplayer_id": {"id": i + 1, "serial": i + 1}}
                for i in range(22)]
        print("squad fetch  -> fallback synthetic entries")
    theirs = [{"gameplayer_id": {"id": 1000 + i, "serial": 1000 + i}}
              for i in range(22)]
    time.sleep(PACE)

    base = c3.sgr_request(LAST_GAME, mine, theirs, 2, 1, "NONE", 328)

    def body(**kw) -> dict:
        b = json.loads(json.dumps(base))          # deep copy
        b.update(kw)
        return b

    # -- error-ordering controls ------------------------------------------
    m = owner.envelope("CMD_CHECK_GAME_RESULT")
    m["game_id"] = 0
    print("CHECK(game_id=0)         -> %s" % brief(owner.send(m)))
    time.sleep(1.2)
    m["game_id"] = 999999999999999999
    print("CHECK(bogus game_id)     -> %s" % brief(owner.send(m)))
    time.sleep(1.2)

    fire(owner, base, "A baseline (real last game)")
    fire(owner, body(game_id=0), "B game_id=0")
    fire(owner, body(game_id=999999999999999999), "C game_id=bogus")

    # -- score axes --------------------------------------------------------
    fire(owner, c3.sgr_request(LAST_GAME, mine, theirs, 0, 0, "NONE", 328),
         "D score 0-0")
    fire(owner, c3.sgr_request(LAST_GAME, mine, theirs, 0, 3, "NONE", 328),
         "E score 0-3")

    # -- the re-added-empty-lists axis -------------------------------------
    full = json.loads(json.dumps(base))
    full["match_result"]["achievement_progress_list"] = []
    full["match_result"]["owngoal_user_list"] = []
    full["match_result"]["behind_flag"] = ["NO"]
    full["match_result"]["tour_pvp_bonus_result_list"] = []
    full["match_result"]["opp_gameplayer_id_list"] = []
    full["game_check_data"]["gameplayer_parameter_check_data_list"] = []
    full["game_check_data"]["opponent_gameplayer_parameter_check_data_list"] \
        = []
    full["game_check_data"]["custom_stadium"]["pitchside_objects"] = []
    fire(owner, full, "F re-added empties (behind [NO])")

    # -- time / reason axes -------------------------------------------------
    fire(owner, c3.sgr_request(LAST_GAME, mine, theirs, 2, 1, "NONE", 0),
         "G frame/tick = 0")
    fire(owner, c3.sgr_request(LAST_GAME, mine, theirs, 2, 1, "", 328),
         "H abnormal = \"\"")

    # -- structural axes ----------------------------------------------------
    only_mr = {"match_result": base["match_result"]}
    fire(owner, only_mr, "I root = match_result only")
    no_mr = {"game_check_data": base["game_check_data"],
             "analyst_set_game_result_info":
                 base["analyst_set_game_result_info"]}
    fire(owner, no_mr, "J root without match_result")

    # -- sender axis ---------------------------------------------------------
    fire(botg, base, "K bot-sent baseline")

    print("probe done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
