#!/usr/bin/env python3
"""sgr_grpc.py -- is CMD_SET_GAME_RESULT a gRPC-stream command?

The gate channel rejects SET_GAME_RESULT with GKZX- even for a completely
empty body (sgr_bisect.py, 60 probes), while CHECK on a bogus game says
JPWM- -- so gate's SET handler refuses before it looks at anything.  The
real phone never sent SET in the captures (that match died at disconnect),
so its channel was never recorded.  The heartbeat taught us the game host
dispatches CommandRequest.id = command name with packMode=0 JSON.

Probes (one-shot CommandStream calls, response id = dispatch oracle):
  1 heartbeat control            -> expect disp=CMD_HEARTBEAT_GRPC
  2 SET_GAME_RESULT JSON body    -> disp? res?
  3 GET_GAME_RESULT JSON control -> a known data command on this channel
  4 SET_GAME_RESULT msgpack       -> expect 14 UNAVAILABLE (consistency)
then a gate-side CHECK on the same game: if probe 2 executed, the verdict
changes from the DISCONN forfeit.
"""
from __future__ import annotations

import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import msgpack  # noqa: E402  (before kgs-login path: stub shadows it)

import chain3 as c3                      # noqa: E402
from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from grpc_beat import beat_call, _req_bytes  # noqa: E402

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\peerlink-efootball-disconnects\kgs-login\scripts")
import kgs_client as kc  # noqa: E402

LAST_GAME = 261000124539290303


def show(tag: str, st: str, gm: str, dec: dict) -> None:
    print("%-34s grpc=%s disp=%r res=%r %s"
          % (tag, st, dec.get("id"), (dec.get("res") or "")[:300],
             gm[:60]))


def json_body(g: Gate, cmd: str, extra: dict) -> bytes:
    env = g.envelope(cmd)
    env.update(extra)
    return json.dumps({k: v for k, v in env.items()
                       if k != "msgid"}).encode()


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
    r = g.send(g.envelope("CMD_CONNECT_GRPC"))
    print("bind (gate)  -> %s" % r.get("result"))
    time.sleep(PACE)

    # 1 heartbeat control: known-good dispatch on this channel
    hb = {k: v for k, v in g.envelope("CMD_HEARTBEAT_GRPC").items()
          if k != "msgid"}
    hb["heartbeat_interval_msec"] = 15000
    st, gm, dec = beat_call("/", json.dumps(hb).encode(), kc.PACK_JSON,
                            "CMD_HEARTBEAT_GRPC")
    show("1 heartbeat control", st, gm, dec)
    time.sleep(1.0)

    # 2 SET_GAME_RESULT over gRPC, full encoder-faithful body
    mine = [{"gameplayer_id": {"id": i + 1, "serial": i + 1}}
            for i in range(22)]
    theirs = [{"gameplayer_id": {"id": 1000 + i, "serial": 1000 + i}}
              for i in range(22)]
    body = c3.sgr_request(LAST_GAME, mine, theirs, 2, 1, "NONE", 328)
    st, gm, dec = beat_call("/", json_body(g, "CMD_SET_GAME_RESULT", body),
                            kc.PACK_JSON, "CMD_SET_GAME_RESULT")
    show("2 SET over gRPC (JSON)", st, gm, dec)
    time.sleep(1.0)

    # 3 read-only data-command control on the same channel
    st, gm, dec = beat_call("/",
                            json_body(g, "CMD_GET_GAME_RESULT",
                                      {"game_id": LAST_GAME}),
                            kc.PACK_JSON, "CMD_GET_GAME_RESULT")
    show("3 GET_GAME_RESULT over gRPC", st, gm, dec)
    time.sleep(1.0)

    # 4 msgpack consistency sample (expected: 14 UNAVAILABLE)
    mp_env = g.envelope("CMD_SET_GAME_RESULT")
    mp_env.update(body)
    msg = _req_bytes("CMD_SET_GAME_RESULT", "/",
                     msgpack.packb(mp_env, use_bin_type=True),
                     kc.PACK_MSGPACK)
    s = kc.connect()
    try:
        frm = b"\x00" + len(msg).to_bytes(4, "big") + msg
        s.sendall(kc.frame(0, 0x1, 1, frm))
        rr = kc.read_frames(s, 4.0)
    finally:
        try:
            s.close()
        except Exception:                              # noqa: BLE001
            pass
    stx, gmx = "-", ""
    for _f, h in rr["headers"]:
        if "grpc-status" in h:
            stx, gmx = h["grpc-status"], h.get("grpc-message", "")
    decx = {}
    if len(rr["data"]) >= 5:
        mlen = int.from_bytes(rr["data"][1:5], "big")
        decx = kc.command_response(rr["data"][5:5 + mlen])
    show("4 SET over gRPC (msgpack)", stx, gmx, decx)
    time.sleep(1.0)

    # did any of that change the server's verdict for the old game?
    m = g.envelope("CMD_CHECK_GAME_RESULT")
    m["game_id"] = LAST_GAME
    c = g.send(m)
    gr = c.get("game_end_result") or {}
    mr = gr.get("match_result") or {}
    sd = mr.get("score_data") or {}
    print("gate CHECK after probes -> %s reason=%s/%s score=%s-%s"
          % (c.get("result"), mr.get("gameend_reason"),
             mr.get("abnormalend_reason"), sd.get("home_score"),
             sd.get("away_score")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
