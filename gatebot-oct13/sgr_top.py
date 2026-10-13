#!/usr/bin/env python3
"""sgr_top.py -- is game_id expected at the ENVELOPE level?

Every SET attempt so far carried game_id only inside match_result; the
top-level copies were only ever tried with 0/bogus values (which a
top-level validator would reject exactly like a missing one).  The client
command object stores game_id as its own member (+0x1e8) beside the msgid,
so the handler may read it as a sibling of msgid.

Probes (all against a remembered, finished game -- if the verdict changes
from GKZX- to anything else, the axis is confirmed without a full match):
  1  top-level game_id = real, empty body
  2  top-level game_id = real, full encoder body
  3  top-level game_id = real + room-ish extras, full body (control+)
  4  top-level game_id = 0, empty body (old control)
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

import chain3 as c3                      # noqa: E402
from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import shape        # noqa: E402

LAST_GAME = 261000124539290303


def fire(g: Gate, extra: dict, body: dict, tag: str) -> None:
    m = g.envelope("CMD_SET_GAME_RESULT")
    m.update(body)
    m.update(extra)          # envelope-level keys LAST: siblings of msgid
    r = g.send(m)
    print("%-42s -> %s (%s)" % (tag, r.get("result"), r.get("errcode")))
    print("  %s" % json.dumps(shape(r), ensure_ascii=False,
                              default=str)[:800])
    time.sleep(1.2)


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
    full = c3.sgr_request(LAST_GAME, mine, theirs, 2, 1, "NONE", 328)

    fire(g, {"game_id": LAST_GAME}, {}, "1 top game_id, empty body")
    fire(g, {"game_id": LAST_GAME}, full, "2 top game_id, full body")
    fire(g, {"game_id": LAST_GAME, "room_id": {"id": 0}}, full,
         "3 top game_id + room_id, full body")
    fire(g, {"game_id": 0}, {}, "4 top game_id=0, empty (control)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
