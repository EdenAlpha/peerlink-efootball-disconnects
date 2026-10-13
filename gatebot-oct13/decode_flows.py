#!/usr/bin/env python3
"""decode_flows.py -- decrypt every block of the 2026-10-12 gate capture.

flows-final.log records the real phone's gate traffic as REQHEX/RESPHEX, which
looks opaque.  It is not: gate_client's cipher key is static, so
gc.decode(bytes.fromhex(...)) opens all 138 blocks (verified: 138/138 OK).

Until now chain3 had only the SEQUENCE from this capture (command names and
order).  This gives the bodies -- including the room / P2P / kickoff window
that the 19-command login-only capture never covered.

  python decode_flows.py                 summary of every block
  python decode_flows.py --cmd CMD_SET_ROOM_MATCH_READY
  python decode_flows.py --from 97 --to 109
  python decode_flows.py --json          machine-readable dump
"""
import json
import re
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import gate_client as gc                                       # noqa: E402
from room_info_shape import SENSITIVE, shape                   # noqa: E402

SENSITIVE.update({"id", "serial"})
LOG = r"C:\Users\Administrator\Documents\Default Project\work\cap\flows-final.log"
SECRET = ("session_id", "s_keyword", "user_id", "auth_code",
          "challenge_code", "ps_session_id", "xb_session_id")


def load():
    """-> [(index, cmd, req|None, resp|None), ...]"""
    txt = open(LOG, encoding="utf-8", errors="replace").read()
    out = []
    i = 0
    for b in txt.split("### REQ POST ")[1:]:
        m = re.match(r"/pes22/gate/gate_(CMD_[A-Z0-9_]+)\.php", b)
        if not m:
            continue
        i += 1
        def dec(rx):
            mm = re.search(rx, b, re.M)
            if not mm:
                return None
            try:
                return gc.decode(bytes.fromhex(mm.group(1)))
            except Exception as e:                              # noqa: BLE001
                return {"_decode_error": str(e)}
        out.append((i, m.group(1), dec(r"^REQHEX: ([0-9a-f]+)$"),
                    dec(r"^RESPHEX: ([0-9a-f]+)$")))
    return out


def scrub(o):
    if isinstance(o, dict):
        return {k: ("<redacted>" if k in SECRET and o[k] not in
                    ("NotImplement", "", 0) else scrub(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [scrub(v) for v in o]
    return o


def main() -> int:
    blocks = load()
    only = None
    lo, hi = 1, 10 ** 9
    as_json = "--json" in sys.argv
    for a in sys.argv[1:]:
        if a.startswith("--cmd"):
            only = a.split("=", 1)[1]
        elif a.startswith("--from"):
            lo = int(a.split("=", 1)[1])
        elif a.startswith("--to"):
            hi = int(a.split("=", 1)[1])

    shown = 0
    for idx, cmd, req, resp in blocks:
        if not (lo <= idx <= hi):
            continue
        if only and cmd != only:
            continue
        shown += 1
        if as_json:
            print(json.dumps({"n": idx, "cmd": cmd,
                              "req": scrub(req), "resp": scrub(resp)},
                             ensure_ascii=False, default=str))
            continue
        print("=" * 78)
        print("%3d  %s" % (idx, cmd))
        if req is not None:
            r = {k: v for k, v in req.items() if k not in ("msgid", "rqid")}
            print("  REQ  %s" % json.dumps(scrub(shape(r)), ensure_ascii=False,
                                           default=str)[:2000])
        if resp is not None:
            r = {k: v for k, v in resp.items() if k not in ("msgid", "rqid")}
            print("  RESP %s" % json.dumps(scrub(shape(r)), ensure_ascii=False,
                                           default=str)[:3000])
    print("=" * 78)
    print("blocks: %d shown" % shown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
