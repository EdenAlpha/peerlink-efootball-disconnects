#!/usr/bin/env python3
"""sgr_bisect.py -- bisect which SET_GAME_RESULT value the server rejects.

The family is open (captured SET_PLAYDATA_MATCH body -> NOERR today); the
GKZX on SET is therefore a VALUE problem.  Suspects, changed one per
variant, from today's settled-verdict vocabulary:

  V0 baseline            23 players (11 start + 12 bench @90min), rating 0,
                         all GK, error_code "0"
  V1 XI only             myteam = the 11 registered at START_GAME
  V2 error_code NOERR    the family's enum vocabulary
  V3 rating 75           plausible player rating instead of 0
  V4 real positions      GK/DF/MF/FW mix instead of all-GK

  python sgr_bisect.py --live <game_id>
"""
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import chain3 as c3                                # noqa: E402
from room1 import Gate, describe, login, load_capture  # noqa: E402

POS = ["GK", "DF", "DF", "DF", "MF", "MF", "MF", "MF", "FW", "FW", "FW"]


def build(game_id, home, away, variant: int) -> dict:
    # V0-V4: player-list / error_code / rating / position sweeps (all GKZX)
    # V5+: enum + optional-block sweep on the remaining invented values
    req = c3.sgr_request(game_id, home, away, 2, 1, "NONE", 320)
    mr = req["match_result"]
    if variant == 5:
        mr["abnormalend_reason"] = "NORMAL"
    elif variant == 6:
        mr["abnormalend_reason"] = ""
    elif variant == 7:
        mr["abnormalend_reason"] = "DISCONN"
    elif variant == 8:
        del mr["ml_event_match_bonus"]
    elif variant == 9:
        del mr["coop_score"]
    elif variant == 10:
        mr["error_code"] = ""
    elif variant == 11:
        mr["error_code"] = 0          # int, not string
    elif variant == 12:
        mr["is_problem"] = "NO"
        mr["user_network_status"] = {"is_stun_connect_failed": "NO",
                                     "is_stun_keep_alive_failed": "NO",
                                     "is_send_keep_alive_failed": "NO",
                                     "is_network_blocked_disconn": "NO"}
    elif variant == 13:
        mr["ex_flag"] = 0
        mr["pk_flag"] = 0
        mr["event_record"] = 0
        mr["restart_num"] = 0
        mr["control_style"] = 0
    elif variant >= 14:
        mr["myteam_player_list"] = mr["myteam_player_list"][:11]
        mr["error_code"] = "NOERR"
        mr["abnormalend_reason"] = "NORMAL"
    return req


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live <game_id>")
        return 0
    game_id = int(sys.argv[sys.argv.index("--live") + 1])

    reqs = load_capture()[0]
    g = Gate()
    ok, r = login(g, reqs)
    print("login -> %s" % (r.get("result") if ok else describe(r)))
    if not ok:
        return 1
    time.sleep(1.0)

    # lineups as the chain registered them (XI = first 11 of each squad)
    sq = g.send(c3.user_squad(g, g.uid))
    home = c3.squad_list(sq)[:11]
    print("lineup -> %d players" % len(home))
    time.sleep(1.0)

    for variant in (5, 6, 7, 8, 9, 10, 11, 12, 13, 14):
        req = build(game_id, home, home, variant)
        m = g.envelope("CMD_SET_GAME_RESULT")
        m.update(req)
        r = g.send(m)
        print("V%d -> %-14s (%s)"
              % (variant, r.get("result"), r.get("errcode")))
        time.sleep(1.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
