#!/usr/bin/env python3
"""dump_turnlist_req.py -- what does the REAL client ask TURN for?

Every probe sends {"turn_account_param":"","turn_time_limit":0} and gets
turn_account.id back as a timestamp that is already expired ("expiry in 0s"),
then 401 on Allocate.  turn_time_limit is a field we chose to zero; if the real
client asks for a non-zero lifetime, the credential may be dead on arrival
before we ever sign a MESSAGE-INTEGRITY.

  python dump_turnlist_req.py
"""
import json
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import decode_flows as DF                                         # noqa: E402


def main() -> int:
    blocks = DF.load()
    print("blocks: %d" % len(blocks))
    hit = 0
    for idx, cmd, req, resp in blocks:
        if "TURN" not in cmd:
            continue
        hit += 1
        print("\n=== block %d  %s ===" % (idx, cmd))
        for tag, r in (("REQ", req), ("RESP", resp)):
            if r is None:
                continue
            r = {k: v for k, v in r.items() if k not in ("msgid", "rqid")}
            print("  %s %s" % (tag, json.dumps(DF.scrub(r), ensure_ascii=False,
                                               default=str)[:1500]))
    if not hit:
        print("\nno TURN command in the capture")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
