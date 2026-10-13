#!/usr/bin/env python3
"""probe_qualitychk.py -- what does CMD_GET_GAMERELAY_QUALITYCHECK_LIST return?

The 2026-10-12 capture sends this BEFORE its three SET_GAMERELAY_QUALITY
reports (blocks 35 -> 38/39/40); chain3 skips it entirely and replays a stale
captured report, which is why game_session lands on sycom=P2P with no relay.

Fast login-only probe: log in as the owner, fetch the list, print the decoded
body (redacted), and exit.  ~20 s.

  python probe_qualitychk.py
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import gate_client as gc                      # noqa: E402
from room1 import Gate, load_capture, login, PACE, describe  # noqa: E402
from room_info_shape import SENSITIVE, shape   # noqa: E402

SENSITIVE.update({"id", "serial"})


def show(o) -> str:
    return json.dumps(shape(o), ensure_ascii=False, default=str)


def walk(o, out):
    """collect region-ish strings anywhere in the reply."""
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(v, str) and v and k.lower() in (
                    "region", "name", "area", "id", "host", "ip_addr"):
                out.setdefault(k, [])
                if v not in out[k]:
                    out[k].append(v)
            walk(v, out)
    elif isinstance(o, list):
        for v in o:
            walk(v, out)


def main() -> int:
    reqs, _resps = load_capture()
    g = Gate()
    ok, r = login(g, reqs)
    print("login -> %s" % (r.get("result") if ok else describe(r)))
    if not ok:
        return 1
    time.sleep(PACE)

    m = g.envelope("CMD_GET_GAMERELAY_QUALITYCHECK_LIST")
    t0 = time.time()
    q = g.send(m, timeout=20)
    print("qualitycheck -> %s  (%.1fs) keys=%s"
          % (q.get("result"), time.time() - t0,
             ",".join(k for k in sorted(q) if k not in ("result", "msgid", "rqid"))))
    print("BODY %s" % show({k: v for k, v in q.items()
                            if k not in ("msgid", "rqid")}))
    found = {}
    walk(q, found)
    print("REGIONS %s" % json.dumps(found, ensure_ascii=False))

    # what the gate considers a complete report
    ql = q.get("quality_list")
    if isinstance(ql, list) and ql:
        print("QUALITY_LIST n=%d first=%s"
              % (len(ql), show(ql[0])))
        print("TOOSEND n=%d -> %s" % (len(ql), show(ql)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
