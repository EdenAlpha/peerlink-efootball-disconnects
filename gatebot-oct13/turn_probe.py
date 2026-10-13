#!/usr/bin/env python3
"""turn_probe.py -- what does CMD_GET_TURN_SERVER_LIST return?

Run #6 (chain3_mapstamp_20261011_145730.log) proved the match is
stamped DISCONN_HB/INVALID immediately after START_GAME: the server
establishes the relay/punch at kickoff and we never speak TURN at all.
First step of the missing conversation (binary-disassembled from
FUN_07f906a4/FUN_07f90c2c, 11.1.0):
  CMD_GET_TURN_SERVER_LIST  -> { turn_account_param, turn_time_limit }
Single read-only request from a logged-in gate identity.
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

from room1 import Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import shape  # noqa: E402


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0
    reqs = load_capture()[0]
    g = Gate()
    ok, r = login(g, reqs)
    print("login -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1
    time.sleep(1.0)

    m = g.envelope("CMD_GET_TURN_SERVER_LIST")
    t = time.time()
    vr = g.send(m)
    print("GET_TURN_SERVER_LIST -> %s  (%.1fs)"
          % (vr.get("result"), time.time() - t))
    body = {k: v for k, v in vr.items()
            if k not in ("result", "msgid", "rqid")}
    print("  shape: %s" % json.dumps(shape(body), ensure_ascii=False,
                                     default=str)[:4000])
    print("  raw:   %s" % json.dumps(body, ensure_ascii=False,
                                     default=str)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
