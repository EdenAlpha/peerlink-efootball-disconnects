#!/usr/bin/env python3
"""grl_probe.py -- send CMD_GET_GAMERESULT_LIST exactly as the game builds it.

Request builder RE'd from 11.1.0 libUE4.so at 0x76eed04 (ctor 0x76eeb??..):
root = this+0xf0, keys in order:

  target_user_id    int32   member +0x1e8   (ctor default 0)
  is_all            string  member +0x1f0   (ctor default "YES")
  match_category    list<string> +0x208..   empty vector -> key OMITTED
  entity_id         int32   member +0x220   (ctor default 0)
  event_ch_mission  string  member +0x228   (ctor default "NotImplement")
  ch_event_type     string  member +0x240   (ctor default "NONE")

Read-only.  One login, two variants at PACE:
  V1 snapshot with target_user_id = own uid (the real "my results" call)
  V2 snapshot with target_user_id = 0       (pure ctor default)

  python grl_probe.py --live
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import SENSITIVE, shape                  # noqa: E402

SENSITIVE.update({"user_id", "target_user_id"})


def grl_body(g: Gate, target: int) -> dict:
    """Exact default-ctor snapshot; only target_user_id differs per variant."""
    return {
        "target_user_id": target,
        "is_all": "YES",
        "entity_id": 0,
        "event_ch_mission": "NotImplement",
        "ch_event_type": "NONE",
    }


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0

    reqs = load_capture()[0]
    g = Gate()
    ok, r = login(g, reqs)
    print("login -> %s" % (r.get("result") if ok else describe(r)))
    if not ok:
        return 1
    time.sleep(PACE)

    for tag, target in (("V1 own-uid", g.uid), ("V2 ctor-default", 0)):
        m = g.envelope("CMD_GET_GAMERESULT_LIST")
        m.update(grl_body(g, target))
        r = g.send(m)
        print("%s -> %s" % (tag, describe(r)))
        for k in ("game_result_list", "player_stats_list", "msg"):
            if k in r:
                print("  %s: %s" % (k, json.dumps(
                    shape(r[k]), ensure_ascii=False, default=str)[:900]))
        time.sleep(PACE)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
