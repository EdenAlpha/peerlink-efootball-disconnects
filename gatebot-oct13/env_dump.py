#!/usr/bin/env python3
"""env_dump.py -- dump CMD_GET_SERVER_ENV in full (redacted).

The ntl family's base URL is a settings default ('HOST_DIRECT' cluster in
.rodata); the server's env blob shows the live values and which knobs the
server controls.  Print the whole decoded response.
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import shape        # noqa: E402


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
    r = g.send(g.envelope("CMD_GET_SERVER_ENV"))
    print("env          -> %s" % r.get("result"))
    txt = json.dumps(shape(r), ensure_ascii=False, default=str, indent=1)
    print("len=%d" % len(txt))
    print(txt[:12000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
