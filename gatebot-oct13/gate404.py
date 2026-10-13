#!/usr/bin/env python3
"""gate404.py -- what does the gate say about a command that cannot exist?

SET_GAME_RESULT has answered GKZX- to EVERY input tried (empty body, full
body, bogus game_id, in-window, late, both identities).  One possibility
that would explain all of it: gate_CMD_SET_GAME_RESULT.php does not exist
in the gate family at all, and the gate's unknown-command answer IS the
GKZX- we have been treating as a body verdict.

  1  gate_CMD_TOTALLY_BOGUS_XYZ.php   (cannot exist)
  2  gate_CMD_SET_GAME_RESULT.php      (empty body)
  3  gate_CMD_CHECK_GAME_RESULT.php    (known-good command, control)

Same envelope for all three; only the msgid (thus the URL) changes.
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import shape        # noqa: E402


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

    r = g.send(g.envelope("CMD_TOTALLY_BOGUS_XYZ"))
    print("1 bogus cmd  -> %s (%s)"
          % (r.get("result"), r.get("errcode")))
    print("  raw: %s" % json.dumps(shape(r), ensure_ascii=False,
                                   default=str)[:900])
    time.sleep(PACE)

    r = g.send(g.envelope("CMD_SET_GAME_RESULT"))
    print("2 SET empty  -> %s (%s)"
          % (r.get("result"), r.get("errcode")))
    print("  raw: %s" % json.dumps(shape(r), ensure_ascii=False,
                                   default=str)[:900])
    time.sleep(PACE)

    r = g.send(g.envelope("CMD_CHECK_GAME_RESULT"))
    print("3 CHECK ctrl -> %s (%s)"
          % (r.get("result"), r.get("errcode")))
    print("  raw: %s" % json.dumps(shape(r), ensure_ascii=False,
                                   default=str)[:900])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
