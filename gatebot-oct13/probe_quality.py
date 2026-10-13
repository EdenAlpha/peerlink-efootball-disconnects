#!/usr/bin/env python3
"""probe_quality.py -- does a COMPLETED relay measurement earn us a gamerelay?

The gate hands us the real relay fleet from
CMD_GET_GAMERELAY_QUALITYCHECK_LIST (regions + addresses on UDP 5521 /
30000 / 50000 -- the exact ports the z2 capture saw the phone probing).
The game then measures them and reports back via
CMD_SET_GAMERELAY_QUALITY {quality_list:[{region,quality,last_update}]}.
chain3.py never fetches the list, never measures, and reports
gamerelay_measure_result="MEASUREING" forever -- so the server has no
reason to assign a relay, and CMD_GET_GAME_SESSION still answers
gamerelay: NotImplement.  No relay -> no LATENCY_MODE_CONNECT session ->
abnormal=DISCONN_HB stamped ~2 s after START_GAME.

This probe: fetch the list, ping a few candidates, report a completed
measurement, then re-read CMD_GET_GAME_SESSION to see whether gamerelay
populated.  One observable answers it.

  python probe_quality.py
"""
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from room1 import Gate, load_capture, login                      # noqa: E402
from room2 import BOT_FILE, login_bot                            # noqa: E402
from chain3 import create_room, entry_side, match_ready, game_session  # noqa: E402

socket.setdefaulttimeout(2.0)


def ping(addr: str):
    """UDP round-trip to a relay candidate -> ms or None.

    address forms seen live:
      "119.40.111.34.bc.googleusercontent.com:443"
      ",22.157.15.34.bc.googleusercontent.com:5521@nogs"
      ",agones-ping.eu-central-2.nabeshin.people.aws.dev:50000@nogs"
    """
    a = addr.lstrip(",")
    a = a.split("@")[0]
    if ":" not in a:
        return None
    host, port = a.rsplit(":", 1)
    try:
        port = int(port)
    except ValueError:
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0]
    except (OSError, socket.gaierror):
        s.close()
        return None
    try:
        t0 = time.time()
        # 30-byte probe: same shape the capture showed the phone sending
        s.sendto(b"\x00" * 30, (ip, port))
        s.recvfrom(2048)
        return (time.time() - t0) * 1000.0
    except (OSError, socket.timeout):
        return None
    finally:
        s.close()


def main() -> int:
    reqs = load_capture()[0]
    owner = Gate()
    ok, _ = login(owner, reqs)
    print("owner login ->", ok)
    if not ok:
        return 1
    botg = Gate()
    with open(BOT_FILE, encoding="utf-8") as fh:
        bot = json.load(fh)
    print("bot login   ->", login_bot(botg, reqs, bot)[0])

    o = create_room(owner)
    rid = ((o.get("room_id") or {}).get("id")) if o.get("result") == "NOERR" else None
    print("create room -> %s rid=%s" % (o.get("result"), rid))
    if not rid:
        return 1
    for side, leader, g in (("HOME", True, owner), ("AWAY", False, botg)):
        print("entry_side  [%s] -> %s" % (side, g.send(entry_side(g, rid, side, leader)).get("result")))
    for tag, g in (("owner", owner), ("bot  ", botg)):
        print("match_ready [%s] -> %s" % (tag, g.send(match_ready(g, rid, "owner" if g is owner else "bot")).get("result")))

    before = owner.send(game_session(owner, rid))
    print("BEFORE gamerelay -> %s" % json.dumps(before.get("gamerelay"), default=str))

    # ---- fetch the relay fleet ----
    ql = owner.send(owner.envelope("CMD_GET_GAMERELAY_QUALITYCHECK_LIST"))
    cands = ql.get("quality_check_data_list") or []
    print("qualitycheck -> %s  %d candidates, threshold_1=%s threshold_2=%s"
          % (ql.get("result"), len(cands),
             ql.get("quality_threshold_1"), ql.get("quality_threshold_2")))
    for c in cands[:4]:
        print("   cand %-22s %s" % (c.get("region"), c.get("address")))

    # ---- measure a handful (regions we can actually reach) ----
    measured, now = [], int(time.time())
    for c in cands:
        if len(measured) >= 6:
            break
        ms = ping(c.get("address") or "")
        if ms is not None:
            measured.append({"region": c.get("region"),
                             "quality": int(ms),
                             "last_update": now})
            print("   measured %-22s %.1f ms" % (c.get("region"), ms))

    if not measured:
        print("no relay answered a UDP probe -- reporting anyway with 0")
        measured = [{"region": cands[0].get("region") if cands else "GLOBAL",
                     "quality": 0, "last_update": now}]

    # ---- report the COMPLETED measurement ----
    variants = [
        ("quality_list only", {"quality_list": measured}),
        ("quality_list+num", {"quality_list": measured,
                              "quality_list_num": len(measured)}),
        ("result MEASUREING", {"gamerelay_measure_result": "MEASUREING",
                               "quality_list": measured}),
    ]
    for label, body in variants:
        m = owner.envelope("CMD_SET_GAMERELAY_QUALITY")
        m.update(body)
        r = owner.send(m)
        print("set_quality [%s] -> %s" % (label, r.get("result")))

    # ---- push the measured list ----
    m = owner.envelope("CMD_SET_LOCAL_GAMERELAY_LIST")
    m["gamerelay_list"] = [
        {"name": "GLOBAL", "region": x["region"], "ip_addr": "",
         "port": 0, "event_id": 0} for x in measured]
    r = owner.send(m)
    print("set_local_gamerelay_list -> %s" % r.get("result"))

    after = owner.send(game_session(owner, rid))
    print("AFTER  gamerelay -> %s" % json.dumps(after.get("gamerelay"), default=str))
    print("AFTER  game_sycom -> %s" % after.get("game_sycom"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
