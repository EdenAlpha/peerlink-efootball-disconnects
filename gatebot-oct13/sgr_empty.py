#!/usr/bin/env python3
"""sgr_empty.py -- the encoder omits empty lists; the server may require them.

gate_map.py showed GKZX- is the standard "your body is missing required
keys" answer.  The real client's serializer omits certain keys entirely
when their source vectors are empty (b.eq guards).  We copied that.  If
the server's required-key set is stricter than the encoder's emit set,
every one of our bodies is missing required keys -> GKZX- always.

Probe 1: full encoder body + every omitted key re-added as [].
Probe 2: control (encoder-faithful, keys omitted).
Probe 3: probe 1 + behind_flag ["NO"] (real-client value when set).
Probe 4: probe 1 with match_json/advice_json filled ("[]").

A verdict change from GKZX- confirms the axis without a match.
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

import chain3 as c3                      # noqa: E402
from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import shape        # noqa: E402

LAST_GAME = 261000124539290303


def fire(g: Gate, req: dict, tag: str) -> None:
    m = g.envelope("CMD_SET_GAME_RESULT")
    m.update(req)
    r = g.send(m)
    print("%-46s -> %s (%s)" % (tag, r.get("result"), r.get("errcode")))
    if r.get("errcode") != "GKZX-":
        print("  %s" % json.dumps(shape(r), ensure_ascii=False,
                                  default=str)[:1200])
    time.sleep(1.2)


def add_empties(b: dict) -> dict:
    b = json.loads(json.dumps(b))
    mr = b["match_result"]
    mr["achievement_progress_list"] = []
    mr["owngoal_user_list"] = []
    mr["behind_flag"] = []
    mr["tour_pvp_bonus_result_list"] = []
    mr["opp_gameplayer_id_list"] = []
    gc = b["game_check_data"]
    gc["gameplayer_parameter_check_data_list"] = []
    gc["opponent_gameplayer_parameter_check_data_list"] = []
    gc["custom_stadium"]["pitchside_objects"] = []
    gc["golazo_info"]["golazo_count_list"] = []
    b["analyst_set_game_result_info"]["advice_info_match"] \
        ["advice_info_list"] = []
    return b


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0

    reqs = load_capture()[0]
    g = Gate()
    ok, r = login(g, reqs)
    print("login        -> %s" % (r.get("result") if ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1
    time.sleep(PACE)

    mine = [{"gameplayer_id": {"id": i + 1, "serial": i + 1}}
            for i in range(22)]
    theirs = [{"gameplayer_id": {"id": 1000 + i, "serial": 1000 + i}}
              for i in range(22)]
    base = c3.sgr_request(LAST_GAME, mine, theirs, 2, 1, "NONE", 328)

    fire(g, add_empties(base), "1 full + every omitted key as []")
    fire(g, base, "2 control (encoder-faithful)")

    p3 = add_empties(base)
    p3["match_result"]["behind_flag"] = ["NO"]
    fire(g, p3, "3 empties + behind_flag [NO]")

    p4 = add_empties(base)
    p4["analyst_set_game_result_info"]["match_json"] = "[]"
    p4["analyst_set_game_result_info"]["advice_json"] = "[]"
    fire(g, p4, "4 empties + match_json/advice_json []")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
