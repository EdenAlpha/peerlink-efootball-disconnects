#!/usr/bin/env python3
"""cap4_probe.py -- replay 4 captured real-client commands, exact bodies.

Discriminator: are session-level preconditions blocking the result family?
These are post-login menu commands the real client sent (captured
2026-10-01-gate, all answered NOERR); we resend them with OUR session and
the captured envelope shapes/bodies verbatim.  Read-only.

  CMD_GET_MAINMENU_INFO        6-key env + {is_skip,is_back,is_first}
  CMD_GET_USEABLE_TEAM_LIST    6-key env + {list_type,event_id}
  CMD_GET_PRODUCT_LIST         6-key env + {}
  CMD_GET_STADIUM_DATA         8-key env (+region,+client_version) + {}

  python cap4_probe.py --live
"""
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import SENSITIVE, shape                  # noqa: E402

SENSITIVE.update({"user_id"})

MIN6 = ("msgid", "rqid", "user_id", "session_id", "my_platform", "s_keyword")

CASES = (
    ("CMD_GET_MAINMENU_INFO", MIN6,
     {"is_skip": "NO", "is_back": "NO", "is_first": "YES"}),
    ("CMD_GET_USEABLE_TEAM_LIST", MIN6,
     {"list_type": "BASE_TEAM_SELECT", "event_id": 0}),
    ("CMD_GET_PRODUCT_LIST", MIN6, {}),
    ("CMD_GET_STADIUM_DATA", MIN6 + ("region", "client_version"), {}),
)


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

    for cmd, envkeys, body in CASES:
        full = g.envelope(cmd)
        msg = {k: full[k] for k in envkeys}
        msg.update(body)
        r = g.send(msg)
        print("%s -> %s" % (cmd, describe(r)))
        if "result" in r and r["result"] == "NOERR":
            extra = {k: r[k] for k in ("gp", "coin_info", "present_num",
                                       "data_list", "use_league_category")
                     if k in r}
            if extra:
                print("   %s" % (shape(extra),))
        time.sleep(1.2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
