"""Probe the two brand-new endpoints found in 11.1.0:
CMD_GET_GAME_SESSION_CHECK_RES  -> CmdGetGameSessionCheckRes.php
CMD_SET_GAME_SESSION_CHECK_RES  -> CmdSetGameSessionCheckRes.php
The LATENCY_MODE_ANNTENA_* names say this is the in-match antenna heartbeat.
Bare probe first: what does the gate say with an empty body?"""
import json
import room1 as r1

g = r1.Gate()
reqs, _resps = r1.load_capture()
ok, info = r1.login(g, reqs)
print("login", ok, r1.describe(info))
if not ok:
    raise SystemExit(1)

for msgid in ("CMD_GET_GAME_SESSION_CHECK_RES",
              "CMD_SET_GAME_SESSION_CHECK_RES"):
    m = g.envelope(msgid)
    r = g.send(m)
    print("---", msgid, "bare ->", r1.describe(r))
    if r.get("result") not in ("NOERR",):
        print("    FULL:", json.dumps(r, ensure_ascii=False, default=str)[:800])

# same but with a room_id + game_session-ish fields, to trigger a field error
m = g.envelope("CMD_SET_GAME_SESSION_CHECK_RES")
m["room_id"] = {"id": 1}
r = g.send(m)
print("--- SET +room_id ->", r1.describe(r))
print("    FULL:", json.dumps(r, ensure_ascii=False, default=str)[:800])
