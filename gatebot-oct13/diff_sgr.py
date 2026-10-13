#!/usr/bin/env python3
"""diff_sgr.py -- our CMD_SET_GAME_RESULT body vs the real captured one.

Run #40 produced the first genuine verdict: gameend=INVALID,
abnormalend_reason=CHEAT, score voided to 0-0.  CHEAT appears nowhere in this
project (not in the 22-code vocabulary, not in the binary enumeration), so the
server is rejecting the content of the report itself.  The obvious suspect is
the anti-tamper payload: game_check_data carries the per-player parameter
lists and ball_move_max_speed, which is exactly what a server can re-derive
from its own stored squad and compare.

chain3's sgr_request was "rebuilt from the real captured client", so this
prints the capture's block-123 body in full next to what chain3 would send,
key by key, and reports only the differences.

  python diff_sgr.py
"""
import json
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import decode_flows as DF                                         # noqa: E402

OUT = r"C:\Users\Administrator\Documents\Default Project\work\cap_sgr123.json"


def walk(d, prefix=""):
    """flatten to dotted paths -> repr(value), truncating big lists"""
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            p = "%s.%s" % (prefix, k) if prefix else str(k)
            out.update(walk(v, p))
    elif isinstance(d, list):
        out[prefix] = ("<list len=%d> %s"
                       % (len(d), json.dumps(d[:2], default=str)[:400]))
    else:
        out[prefix] = repr(d)
    return out


def main() -> int:
    blocks = DF.load()
    target = None
    for idx, cmd, req, resp in blocks:
        if cmd == "CMD_SET_GAME_RESULT" and idx == 123:
            target = req
            break
    if target is None:
        for idx, cmd, req, resp in blocks:
            if cmd == "CMD_SET_GAME_RESULT":
                target = req
                print("using block #%d (123 not found)" % idx)
                break
    if target is None:
        print("no CMD_SET_GAME_RESULT in the capture")
        return 1

    print("=== capture block 123, TOP-LEVEL keys ===")
    print("  %s" % sorted(target))

    print("\n=== root game_id present? ===")
    print("  root game_id      = %r" % target.get("game_id"))
    mr = target.get("match_result") or {}
    print("  match_result.game_id = %r" % mr.get("game_id"))

    gcd = target.get("game_check_data") or {}
    print("\n=== capture game_check_data (anti-tamper payload) ===")
    for k in sorted(gcd):
        v = gcd[k]
        if isinstance(v, list):
            print("  %-45s list len=%d  first=%s"
                  % (k, len(v), json.dumps(v[:1], default=str)[:220]))
        elif isinstance(v, dict):
            print("  %-45s dict keys=%s" % (k, sorted(v)))
        else:
            print("  %-45s %r" % (k, v))

    print("\n=== capture match_result scalar fields ===")
    for k in sorted(mr):
        v = mr[k]
        if not isinstance(v, (dict, list)):
            print("  %-45s %r" % (k, v))

    print("\n=== capture match_result list/dict fields ===")
    for k in sorted(mr):
        v = mr[k]
        if isinstance(v, list):
            print("  %-45s list len=%d" % (k, len(v)))
        elif isinstance(v, dict):
            print("  %-45s dict keys=%s" % (k, sorted(v)))

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(target, f, indent=1, ensure_ascii=False, default=str)
    print("\nfull capture body written to %s" % OUT)

    # now what chain3 would send, for the same shape
    print("\n=== chain3 sgr_request output, same view ===")
    import chain3                                          # noqa: E402
    home = [{"gameplayer_id": {"id": i, "serial": i}, "position": "CM",
             "rating": 600, "play_time": 90} for i in range(23)]
    away = [{"gameplayer_id": {"id": 100 + i, "serial": i}, "position": "CM",
             "rating": 600, "play_time": 90} for i in range(23)]
    req = chain3.sgr_request(123, home, away, 2, 1, "NOERR", 389)
    print("  our top-level keys   %s" % sorted(req))
    og = req.get("game_check_data") or {}
    print("  our gcd keys         %s" % sorted(og))
    cg = set(gcd)
    tg = set(og)
    print("\n  gcd keys MISSING from ours : %s" % sorted(cg - tg))
    print("  gcd keys EXTRA in ours     : %s" % sorted(tg - cg))
    for k in sorted(cg & tg):
        cv, ov = gcd[k], og[k]
        if isinstance(cv, list) and isinstance(ov, list):
            if len(cv) != len(ov):
                print("  gcd len differs %-40s cap=%d ours=%d"
                      % (k, len(cv), len(ov)))
        elif json.dumps(cv, default=str) != json.dumps(ov, default=str):
            print("  gcd differs     %-40s cap=%r ours=%r"
                  % (k, str(cv)[:80], str(ov)[:80]))

    cm, om = set(mr), set(req.get("match_result") or {})
    print("\n  match_result MISSING from ours : %s" % sorted(cm - om))
    print("  match_result EXTRA in ours     : %s" % sorted(om - cm))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
