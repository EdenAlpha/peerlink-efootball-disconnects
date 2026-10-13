#!/usr/bin/env python3
"""bot_second.py -- can a second bot session coexist with the holder?

The holder process owns the bot session that keeps room 17699979 alive.
Driving the ladder (squad/side/ready) needs a bot session elsewhere.
This logs the bot in a SECOND session and only reads room info; if the
holder keeps polling NOERR afterwards, sessions coexist and the ladder
can be driven from a separate script.

  python bot_second.py --live <room_id>
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

from room1 import PACE, Gate, describe, load_capture   # noqa: E402
from room2 import BOT_FILE, login_bot                  # noqa: E402
from room_info_shape import SENSITIVE, shape           # noqa: E402

SENSITIVE.update({"user_id"})


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live <room_id>")
        return 0
    rid = int(sys.argv[sys.argv.index("--live") + 1])

    bot = json.load(open(BOT_FILE, encoding="utf-8"))
    reqs = load_capture()[0]
    g = Gate()
    ok, r = login_bot(g, reqs, bot)
    print("bot login (2nd session) -> %s" % (r.get("result")
                                             if ok else describe(r)))
    if not ok:
        return 1
    time.sleep(PACE)

    m = g.envelope("CMD_GET_ROOM_INFO")
    m.update({"mode": "CUSTOM", "id": 0, "room_id": {"id": rid},
              "event_id": 0, "user_compe_id": 0, "is_room_search": "NO"})
    ri = g.send(m)
    info = ri.get("room_info") or {}
    print("room_info -> %s num_users=%s"
          % (ri.get("result"), info.get("num_users")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
