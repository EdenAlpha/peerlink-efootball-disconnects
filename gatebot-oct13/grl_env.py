#!/usr/bin/env python3
"""grl_env.py -- CMD_GET_GAMERESULT_LIST under envelope variants.

Ground truth (decrypted committed capture, 2026-10-01-gate):
the real client's CMD_SET_PLAYDATA_MATCH (same family that GKZX-walls us)
carried a 6-key envelope -- msgid, rqid, user_id, session_id, my_platform,
s_keyword -- and got NOERR.  We always send 10 keys (extra lang, region,
platform, client_version); even our "empty body" probes carried those 4,
so a strict handler would answer GKZX- ("unknown args") to EVERY variant.

Same exact RE-built body in all three; only the envelope varies:
  V1 6 keys (real client shape), normal rqid
  V2 6 keys, time-based rqid (~1.79e9, like the capture's ~1.94e9)
  V3 8 keys (+lang,+platform -- most common captured non-login shape)

  python grl_env.py --live
"""
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import SENSITIVE, shape                  # noqa: E402

SENSITIVE.update({"user_id", "target_user_id"})

MIN6 = ("msgid", "rqid", "user_id", "session_id", "my_platform", "s_keyword")


def grl_body(g: Gate) -> dict:
    """Exact default-ctor snapshot from 11.1.0 RE at 0x76eed04."""
    return {
        "target_user_id": g.uid,
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

    variants = []

    m = g.envelope("CMD_GET_GAMERESULT_LIST")
    variants.append(("V1 6key", {k: m[k] for k in MIN6}))

    m = g.envelope("CMD_GET_GAMERESULT_LIST")
    m["rqid"] = int(time.time() * 1000) % (1 << 31)
    variants.append(("V2 6key+msrqid", {k: m[k] for k in MIN6}))

    m = g.envelope("CMD_GET_GAMERESULT_LIST")
    variants.append(("V3 8key", {k: m[k] for k in MIN6 + ("lang", "platform")}))

    for tag, env in variants:
        msg = dict(env)
        msg.update(grl_body(g))
        r = g.send(msg)
        print("%s -> %s" % (tag, describe(r)))
        for k in ("msg", "game_result_list"):
            if k in r:
                print("  %s: %s" % (k, shape(r[k])))
        time.sleep(1.2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
