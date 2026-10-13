#!/usr/bin/env python3
"""verdict_full.py -- dump the FULL match_result the server builds (read-only).

The server constructs the complete match_result template in
CMD_GET_GAME_RESULT.  Now that proven bodies matter more than schemas,
this is the value dictionary to echo from for SET_GAME_RESULT.

  python verdict_full.py --live [room_id]
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
from room_info_shape import SENSITIVE, shape  # noqa: E402

SENSITIVE.update({"user_id", "target_user_id"})


def walk(v, depth=0):
    """structure-only view, deep enough to read lists of scalars"""
    if isinstance(v, dict):
        if depth >= 3:
            return "{%s}" % ", ".join(v)
        return {k: ("<redacted>" if k in SENSITIVE else walk(x, depth + 1))
                for k, x in v.items()}
    if isinstance(v, list):
        if not v:
            return "[0]"
        return "[%d x %s]" % (len(v), walk(v[0], depth + 1))
    if isinstance(v, str) and len(v) > 48:
        return "str(len=%d)" % len(v)
    return v


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live [room_id]")
        return 0
    idx = sys.argv.index("--live")
    rid = (int(sys.argv[idx + 1]) if len(sys.argv) > idx + 1
           and sys.argv[idx + 1].isdigit() else 14846692)

    reqs = load_capture()[0]
    bot = json.load(open(BOT_FILE, encoding="utf-8"))

    owner = Gate()
    ok, r = login(owner, reqs)
    print("owner login -> %s" % (r.get("result") if ok else describe(r)))
    if not ok:
        return 1
    time.sleep(PACE)

    game_id = c3.get_game_id(owner, rid)
    if game_id is None:
        print("no game_id in room %s" % rid)
        return 1
    print("game_id -> ok")
    time.sleep(PACE)

    m = owner.envelope("CMD_GET_GAME_RESULT")
    m["game_id"] = game_id
    r = owner.send(m)
    print("CMD_GET_GAME_RESULT -> %s" % describe(r))
    mr = r.get("match_result")
    if not isinstance(mr, dict):
        print("  (no match_result; keys: %s)" % list(r))
        return 0
    print("match_result keys (%d): %s" % (len(mr), list(mr)))
    print(json.dumps(walk(mr), ensure_ascii=False, indent=1,
                     default=str)[:6000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
