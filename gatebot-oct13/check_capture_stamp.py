#!/usr/bin/env python3
"""check_capture_stamp.py -- did the SERVER ever say DISCONN_HB to a real client?

Everything so far treats `abnormalend_reason: DISCONN_HB` as a stamp the server
applies.  Run #38 showed it is already present in CMD_CHECK_GAME_RESULT BEFORE
either side kicks off, which would make it a standing default for "no result
yet" rather than a verdict.  The 2026-10-12 real-client capture settles it: if
a genuine match's responses never carry DISCONN_HB, the value is not part of
normal traffic; if they do, it is ordinary and only gameend_reason matters.

grep on flows-final.log is not evidence either way -- the payloads are
gate-encrypted, so this decodes all 138 blocks and searches the plaintext.

  python check_capture_stamp.py
"""
import json
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import decode_flows as DF                                         # noqa: E402

TERMS = ("DISCONN", "abnormalend_reason", "gameend_reason",
         "NORMAL_END", "INVALID", "game_res")


def main() -> int:
    blocks = DF.load()
    print("blocks decoded: %d" % len(blocks))

    # 1. does DISCONN_HB appear anywhere at all, request or response?
    anywhere = []
    for idx, cmd, req, resp in blocks:
        for label, obj in (("REQ", req), ("RESP", resp)):
            s = json.dumps(obj, ensure_ascii=False, default=str)
            for t in ("DISCONN_HB", "DISCONN_SC", "DISCONN_SLEEP", "NORMAL_END",
                      "NO_OPERATION", "NORMAL_GIVEUP"):
                if t in s:
                    anywhere.append((idx, cmd, label, t))

    print("\n=== abnormalend vocabulary seen in the real capture ===")
    if anywhere:
        seen = {}
        for idx, cmd, label, t in anywhere:
            seen.setdefault(t, []).append("%s/%s#%d" % (label, cmd, idx))
        for t, where in sorted(seen.items()):
            print("  %-16s %d  e.g. %s" % (t, len(where), ", ".join(where[:4])))
    else:
        print("  NONE -- no abnormalend token of any kind is in the capture")

    # 2. every response carrying gameend_reason / game_res
    print("\n=== responses containing gameend_reason / game_res ===")
    n = 0
    for idx, cmd, req, resp in blocks:
        s = json.dumps(resp, ensure_ascii=False, default=str)
        if "gameend_reason" in s or '"game_res"' in s:
            n += 1
            mr = {}
            for key in ("game_end_result", "match_result"):
                v = resp.get(key)
                if isinstance(v, dict):
                    mr = v.get("match_result") or v
            print("  #%-4d %-24s gameend=%s abnormal=%s game_res=%s score=%s"
                  % (idx, cmd, mr.get("gameend_reason"),
                     mr.get("abnormalend_reason"), mr.get("game_res"),
                     mr.get("score_data")))
            if n <= 3:
                print("        keys=%s" % sorted(resp))
    if n == 0:
        print("  none -- the capture contains NO resolved match verdict")

    # 3. the one SET_GAME_RESULT the real client sent, and what followed
    print("\n=== SET_GAME_RESULT -> GET_GAME_RESULT sequence ===")
    for idx, cmd, req, resp in blocks:
        if cmd in ("CMD_SET_GAME_RESULT", "CMD_GET_GAME_RESULT"):
            mr = req.get("match_result") or {}
            out = resp.get("match_result") or \
                (resp.get("game_end_result") or {}).get("match_result") or {}
            print("  #%-4d %-24s -> %-8s  req abnormal=%s | resp gameend=%s"
                  " abnormal=%s get_match_result=%s"
                  % (idx, cmd, resp.get("result"),
                     mr.get("abnormalend_reason"), out.get("gameend_reason"),
                     out.get("abnormalend_reason"),
                     resp.get("get_match_result")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
