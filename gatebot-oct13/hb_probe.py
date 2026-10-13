#!/usr/bin/env python3
"""hb_probe.py -- what do the gRPC control commands answer over the PROVEN
gate HTTP channel?

Background: the real game holds one gRPC CommandStream to
pes22-game.cs.konami.net:443 and beats every 15.0 s for the whole match
(pass-through capture).  The stream's route table is unsolved (only path="/"
resolves -> CMD_END_CONNECTION), so before touching the stream we ask the
gate, where every command we have tried works:

  1. CMD_CONNECT_GRPC   envelope-only body  -> does it return stream params
     (server address/port/path/session token)?  That would hand us the route.
  2. CMD_HEARTBEAT_GRPC {heartbeat_interval_msec:15000} -> status + body.

One fresh login run, two calls, everything printed through describe()
(includes _status for empty bodies).
"""
from __future__ import annotations

import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import shape  # noqa: E402


def show(o: dict) -> None:
    print("  %s" % json.dumps(shape(o), ensure_ascii=False, default=str)[:1200])


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0
    reqs = load_capture()[0]
    g = Gate()
    ok, r = login(g, reqs)
    print("login        -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1

    time.sleep(PACE)
    m = g.envelope("CMD_GET_SERVER_ENV")
    r = g.send(m)
    print("server_env   -> %s" % r.get("result"))
    print("  %s" % describe(r))
    for k in ("proto_opt", "onsys_opt"):
        if isinstance(r.get(k), str):
            print("  %s = %s" % (k, r[k]))
    hits = [k for k in r if any(w in k.lower()
                                for w in ("grpc", "heartbeat", "stream",
                                          "interval", "connect"))]
    for k in hits:
        print("  key %s = %r" % (k, r[k]))
    print("  all keys: %s" % ",".join(sorted(r)))
    blob = json.dumps(shape(r), ensure_ascii=False, default=str)
    for m in __import__("re").finditer(r".{50}grpc.{70}", blob,
                                        __import__("re").I):
        print("  ctx: %s" % m.group(0))
    show({k: v for k, v in r.items() if k not in ("msgid", "rqid")})

    time.sleep(PACE)
    m = g.envelope("CMD_CONNECT_GRPC")
    r = g.send(m)
    print("connect_grpc -> %s" % r.get("result"))
    print("  %s" % describe(r))
    show({k: v for k, v in r.items() if k not in ("msgid", "rqid")})

    time.sleep(PACE)
    m = g.envelope("CMD_HEARTBEAT_GRPC")
    m["heartbeat_interval_msec"] = 15000
    r = g.send(m)
    print("heartbeat    -> %s" % r.get("result"))
    print("  %s" % describe(r))
    if r.get("result") not in ("NOERR", "_HTTP_EMPTY"):
        show({k: v for k, v in r.items() if k not in ("msgid", "rqid")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
