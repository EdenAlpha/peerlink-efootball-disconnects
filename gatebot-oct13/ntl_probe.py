#!/usr/bin/env python3
"""ntl_probe.py -- does the result command live on the ntl family?

The APK embeds a second transport: http://ntl.service.konami.net/ntl/api/
(census: GateInfo.php + ReportLog.php seen on port 80; Cmd*.php names
never seen only because that match died before any result was sent).
Each command object stores BOTH its gate msgid and its ntl Cmd*.php name,
so the result commands may be ntl-only while the gate's handler is a stub
that always answers GKZX-.

Same signed-msgpack codec as the gate (their own HTTP layer), posted to:

  1  /ntl/api/PES2022/CmdSetGameResult.php      (SET, full body)
  2  /ntl/api/CmdSetGameResult.php              (no PES2022 segment)
  3  /ntl/api/PES2022/CmdCheckGameResult.php    (read-only control)
  4  /ntl/api/GateInfo.php                      (census-proven live)
  5  https game host, ntl path                  (both families, one host)
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import chain3 as c3                      # noqa: E402
import gate_client as gc                 # noqa: E402
from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402
from room_info_shape import shape        # noqa: E402

NTL = "http://ntl.service.konami.net"
LAST_GAME = 261000124539290303


def post_path(path: str, body: bytes, sign: str, host: str,
              port: int, tls: bool, timeout: int = 15):
    import http.client
    import ssl
    if tls:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        conn = http.client.HTTPSConnection(host, port, context=ctx,
                                           timeout=timeout)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    hdrs = dict(gc.headers_for(body, sign))
    hdrs["Host"] = host
    conn.request("POST", path, body=body, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    out = (resp.status, resp.reason, dict(resp.getheaders()), data)
    conn.close()
    return out


def fire(tag: str, path: str, msg: dict, host: str = "ntl.service.konami.net",
         port: int = 80, tls: bool = False) -> None:
    body = gc.encode(msg)
    sign = gc.make_sign(body)
    try:
        status, reason, hdrs, data = post_path(path, body, sign, host,
                                               port, tls)
    except Exception as ex:                          # noqa: BLE001
        print("%-52s -> EXC %s" % (tag, str(ex)[:100]))
        return
    dec = None
    try:
        dec = gc.decode(data)
    except Exception:                                # noqa: BLE001
        pass
    print("%-52s -> %d %s" % (tag, status, reason))
    if dec is not None:
        print("  decoded: %s" % json.dumps(shape(dec), ensure_ascii=False,
                                           default=str)[:900])
    else:
        print("  raw(%dB): %r" % (len(data), data[:220]))


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

    mine = [{"gameplayer_id": {"id": i + 1, "serial": i + 1}}
            for i in range(22)]
    theirs = [{"gameplayer_id": {"id": 1000 + i, "serial": 1000 + i}}
              for i in range(22)]
    sgr = c3.sgr_request(LAST_GAME, mine, theirs, 2, 1, "NONE", 328)

    mset = g.envelope("CMD_SET_GAME_RESULT")
    mset.update(sgr)
    mchk = g.envelope("CMD_CHECK_GAME_RESULT")
    mchk["game_id"] = LAST_GAME
    minfo = g.envelope("CMD_GET_SERVER_ENV")     # any valid envelope

    fire("1 ntl/PES2022/CmdSetGameResult", "/ntl/api/PES2022/"
         "CmdSetGameResult.php", mset)
    fire("2 ntl/CmdSetGameResult", "/ntl/api/CmdSetGameResult.php", mset)
    fire("3 ntl/PES2022/CmdCheckGameResult (ctl)",
         "/ntl/api/PES2022/CmdCheckGameResult.php", mchk)
    fire("4 ntl/PES2022/GateInfo (ctl)", "/ntl/api/PES2022/GateInfo.php",
         minfo)
    fire("5 ntl/api/GateInfo (census path)", "/ntl/api/GateInfo.php",
         minfo)
    fire("6 game-host ntl path", "/ntl/api/PES2022/CmdSetGameResult.php",
         mset, host="pes22-game.cs.konami.net", port=443, tls=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
