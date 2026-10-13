#!/usr/bin/env python3
"""play_probe.py -- replay the captured real CMD_SET_PLAYDATA_MATCH body.

The committed capture holds the real client's passing request (NOERR):
6-key envelope + {play_data, match_team_play_data} as two JSON strings.
Every earlier result-family probe used guessed/default values, which is
now the leading explanation of the GKZX wall.  This replays the captured
body verbatim under the throwaway BOT identity (never the owner).

  python play_probe.py --live
"""
import json
import re
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import cap_dec                                              # noqa: E402
from room1 import PACE, Gate, describe, load_capture        # noqa: E402
from room2 import BOT_FILE, login_bot                       # noqa: E402

MIN6 = ("msgid", "rqid", "user_id", "session_id", "my_platform", "s_keyword")


def captured_playdata() -> dict:
    txt = open(cap_dec.CAP, encoding="utf-8", errors="replace").read()
    for b in re.split(r"(?=^### )", txt.replace("\r\n", "\n"), flags=re.M):
        if "### REQ POST /pes22/gate/gate_CMD_SET_PLAYDATA_MATCH" in b:
            me = re.search(r"^REQHEX: ([0-9a-f]+)\s*$", b, flags=re.M)
            m = cap_dec.dec(bytes.fromhex(me.group(1)))
            return {k: m[k] for k in ("play_data", "match_team_play_data")}
    raise SystemExit("captured SET_PLAYDATA_MATCH block not found")


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0

    bot = json.load(open(BOT_FILE, encoding="utf-8"))
    reqs = load_capture()[0]
    g = Gate()
    ok, r = login_bot(g, reqs, bot)
    print("bot login -> %s" % (r.get("result") if ok else describe(r)))
    if not ok:
        return 1
    time.sleep(PACE)

    body = captured_playdata()
    print("captured body: %s" % {k: "json(len=%d)" % len(v)
                                 for k, v in body.items()})
    full = g.envelope("CMD_SET_PLAYDATA_MATCH")
    msg = {k: full[k] for k in MIN6}
    msg.update(body)
    r = g.send(msg, timeout=40)
    print("SET_PLAYDATA_MATCH (captured body) -> %s" % describe(r))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
