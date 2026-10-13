#!/usr/bin/env python3
"""hist_probe.py -- read a REAL stored match result (server-side template).

SET_GAME_RESULT is a 100%-rejection wall (~150 probes, two eras, every
axis).  But these accounts have played real matches on real phones; the
server STORED those results.  CMD_GET_GAMERESULT_LIST (handler exists,
gate_map.py) should return the exact structure a real client's accepted
SET produced -- the ground-truth template we have never had.

Args unknown; probe common shapes at ~1 s pace and print any response
that is not GKZX-.
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room2 import BOT_FILE, login_bot    # noqa: E402
from room_info_shape import shape        # noqa: E402


def fire(g: Gate, extra: dict, tag: str) -> None:
    m = g.envelope("CMD_GET_GAMERESULT_LIST")
    m.update(extra)
    r = g.send(m)
    print("%-40s -> %s (%s)" % (tag, r.get("result"), r.get("errcode")))
    if r.get("errcode") not in ("GKZX-",):
        print("  %s" % json.dumps(shape(r), ensure_ascii=False,
                                  default=str)[:2200])
    time.sleep(1.2)


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

    g = Gate()
    ok, r = login(g, reqs)
    print("login        -> %s" % (r.get("result") if ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1
    time.sleep(PACE)

    fire(g, {}, "1 empty")
    fire(g, {"user_id": g.uid}, "2 user_id")
    fire(g, {"user_id": g.uid, "count": 10}, "3 user_id+count")
    fire(g, {"user_id": g.uid, "limit": 10, "offset": 0},
         "4 user_id+limit+offset")
    fire(g, {"target_user_id": g.uid}, "5 target_user_id")
    fire(g, {"game_id": 0}, "6 game_id=0")
    fire(g, {"user_id": g.uid, "offset": 0, "count": 5,
             "match_category": "CUSTOM"}, "7 +match_category")
    fire(g, {"user_id": g.uid, "mode": "CUSTOM"}, "8 +mode")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
