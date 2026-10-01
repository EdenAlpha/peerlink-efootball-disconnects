#!/usr/bin/env python3
"""Self-tests for kgs_session.py. Run: python test_kgs_session.py [--live]

No pytest on this box, and the repo's other checks are plain scripts, so this
follows the same shape.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kgs_client as kc  # noqa: E402
import kgs_session as ks  # noqa: E402

FAILED = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name} {detail}")
        FAILED.append(name)


def test_stream_id() -> None:
    # connect() opens the stream on 1; DATA must follow or the server is silent.
    check("stream id is 1", ks.Session.STREAM_ID == 1,
          f"got {ks.Session.STREAM_ID}")


def test_request_shape() -> None:
    msg = kc.command_request("ID", "CMD_LOGIN", "{}", kc.PACK_JSON)
    # field 4 (wire tag 0x22) must be present and must carry the path.
    idx = msg.find(b"\x22")
    check("field 4 tag present", idx >= 0)
    if idx >= 0:
        ln = msg[idx + 1]
        got = msg[idx + 2:idx + 2 + ln].decode()
        check("field 4 is the path", got == "CMD_LOGIN", f"got {got!r}")
    # field 3 (0x1a) is req, field 1 (0x0a) is id.
    check("field 3 tag present", msg.find(b"\x1a") >= 0)
    check("field 1 tag present", msg.find(b"\x0a") >= 0)
    # field 2 (0x10) is packMode = 0 -> a single 0x00 byte.
    check("packMode JSON encoded as 0", b"\x10\x00" in msg)


def test_find_code() -> None:
    check("finds top-level code",
          ks.find_code('{"recruitCode":"123456"}') == "123456")
    check("finds nested code",
          ks.find_code('{"a":{"b":[{"room_code":"778899"}]}}') == "778899")
    check("ignores unrelated body",
          ks.find_code('{"result":"NOERR"}') is None)
    check("ignores non-json", ks.find_code("not json") is None)
    check("ignores empty", ks.find_code("") is None)


def test_route_parsing() -> None:
    steps = ks.load_routes()
    check("routes file yields steps", len(steps) >= 1, f"got {steps}")
    check("every step is a 2-tuple",
          all(isinstance(s, tuple) and len(s) == 2 for s in steps))
    routes = [s[0] for s in steps]
    check("session id step first", routes[0] == "CMD_GET_SESSION_ID",
          f"got {routes[0] if routes else None}")
    check("login before room",
          "CMD_LOGIN" in routes
          and routes.index("CMD_LOGIN") < (routes.index("CMD_CREATEJOIN_ROOM")
                                           if "CMD_CREATEJOIN_ROOM" in routes
                                           else 99))


def test_missing_payload_is_flagged() -> None:
    payload, prov = ks.load_payload("CMD_LOGIN", None)
    check("missing payload yields {}", payload == "{}", f"got {payload!r}")
    check("provenance records the gap",
          prov in ("empty",) or prov.startswith("MISSING"), f"got {prov!r}")


def test_live_control() -> None:
    """Both halves of the 14 story, against the real server.

    '/' is known to resolve (kgs_client reports {"result":"NOERR"}); a
    nonsense route must come back 14. Needs network.
    """
    print("  .. live checks (network)")
    ok = ks.run([("/", None)], 10.0, None)
    check("known route answered", ok == 5, f"exit {ok}")

    ok = ks.run([("this_command_does_not_exist", None)], 10.0, None)
    check("unknown route reports 14", ok == 4, f"exit {ok}")


def main() -> int:
    print("test_kgs_session")
    test_stream_id()
    test_request_shape()
    test_find_code()
    test_route_parsing()
    test_missing_payload_is_flagged()
    if "--live" in sys.argv:
        test_live_control()
    else:
        print("  (skipping live checks; pass --live to include them)")

    if FAILED:
        print(f"\n{len(FAILED)} FAILED: {', '.join(FAILED)}")
        return 1
    print("\nall passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
