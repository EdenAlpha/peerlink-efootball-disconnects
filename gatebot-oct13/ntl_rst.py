#!/usr/bin/env python3
"""ntl_rst.py -- is /ntl/api/CmdSetGameResult.php a real path?

ntl_probe.py: /ntl/api/CmdSetGameResult.php -> connection RESET while
known-real /ntl/api/GateInfo.php -> 200 and dead paths -> 404.  Repeat
each a few times on fresh connections: real path vs fake path vs known
real, to see whether the reset is a consistent existence signal.
"""
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import gate_client as gc                 # noqa: E402

PATHS = [
    ("/ntl/api/CmdSetGameResult.php", 3),
    ("/ntl/api/CmdCheckGameResult.php", 2),
    ("/ntl/api/CmdSetGameResultXyz9.php", 2),
    ("/ntl/api/GateInfo.php", 1),
]


def one(path: str, body: bytes, sign: str) -> str:
    import http.client
    conn = http.client.HTTPConnection("ntl.service.konami.net", 80,
                                      timeout=15)
    hdrs = dict(gc.headers_for(body, sign))
    hdrs["Host"] = "ntl.service.konami.net"
    try:
        conn.request("POST", path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return "%d %s  %r" % (resp.status, resp.reason, data[:80])
    except Exception as ex:                          # noqa: BLE001
        return "EXC %s" % str(ex)[:90]
    finally:
        try:
            conn.close()
        except Exception:                            # noqa: BLE001
            pass


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0
    body = gc.encode({"msgid": "CMD_GET_SERVER_ENV", "rqid": 1,
                      "lang": "US"})
    sign = gc.make_sign(body)
    for path, n in PATHS:
        for i in range(n):
            print("%-42s #%d -> %s" % (path, i + 1, one(path, body, sign)))
            time.sleep(1.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
