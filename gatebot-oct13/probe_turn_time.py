#!/usr/bin/env python3
"""probe_turn_time.py -- is our TURN credential expired the moment we get it?

dump_turnlist_req.py showed the real client never issues
CMD_GET_TURN_SERVER_LIST inside the captured window, so both request fields
were our own invention -- in particular turn_time_limit: 0.  The reply comes
back with turn_account.id equal to a unix timestamp that is ALREADY in the
past ("expiry in 0s"), and every Allocate built on it is rejected 401.

This sweeps turn_time_limit and reports how the returned credential's lifetime
moves, which tells us whether the id is an expiry we control or a fixed
stamp the server ignores.

  python probe_turn_time.py
"""
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import Gate, load_capture, login, PACE, describe       # noqa: E402

PARAMS = [0, 1, 60, 300, 1800, 3600, 86400]


def ask(g, param, limit, tapp):
    m = g.envelope("CMD_GET_TURN_SERVER_LIST")
    m["turn_account_param"] = param
    m["turn_time_limit"] = limit
    if tapp is not None:
        m["turn_account_param_extra"] = tapp
    r = g.send(m, timeout=15)
    return r


def main() -> int:
    reqs, _ = load_capture()
    g = Gate()
    ok, r = login(g, reqs)
    if not ok:
        print("login failed: %s" % describe(r))
        return 1

    now = int(time.time())
    print("now = %d\n" % now)
    print("%-14s %-8s %-14s %-12s %s" %
          ("turn_time_limit", "result", "id", "delta(id-now)", "pw len"))
    print("-" * 66)
    for lim in PARAMS:
        try:
            r = ask(g, "", lim, None)
        except Exception as e:                                    # noqa: BLE001
            print("%-14s ERR %s" % (lim, e))
            continue
        res = r.get("result")
        acc = r.get("turn_account") or {}
        aid = str(acc.get("id", ""))
        pw = str(acc.get("pw", ""))
        if aid.isdigit():
            d = int(aid) - now
            print("%-14s %-8s %-14s %-12s %d" % (lim, res, aid, "%+ds" % d,
                                                 len(pw)))
        else:
            print("%-14s %-8s %-14r %-12s %d" % (lim, res, aid, "-",
                                                 len(pw)))
        print("        keys: %s" % ",".join(sorted(acc.keys())))
        time.sleep(PACE)

    # does an explicit turn_account_param revive anything?
    print("\n=== turn_account_param variations (limit 3600) ===")
    for p in ("1", "0", "me"):
        try:
            r = ask(g, p, 3600, None)
        except Exception as e:                                    # noqa: BLE001
            print("  param=%r ERR %s" % (p, e))
            continue
        acc = r.get("turn_account") or {}
        aid = str(acc.get("id", ""))
        d = (int(aid) - now) if aid.isdigit() else None
        print("  param=%-4r result=%-8s id=%r delta=%s"
              % (p, r.get("result"), aid, ("%+ds" % d) if d is not None else "-"))
        time.sleep(PACE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
