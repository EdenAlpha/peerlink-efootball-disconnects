#!/usr/bin/env python3
"""dump the REAL captured match flow (cap/flows-final.log), reusing dump_flow's
parser+decoder.  This is the room-create -> join -> ready -> kickoff -> ingame
-> result sequence of a genuine client, which is what chain3 has been missing.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import dump_flow as df  # noqa: E402

FINAL = os.path.join(HERE, "cap", "flows-final.log")

KEY = {
    "CMD_LOGIN", "CMD_CREATEJOIN_ROOM", "CMD_CHECK_MATCH_ENABLE",
    "CMD_SET_ROOM_MATCH_READY", "CMD_GET_GAME_SESSION",
    "CMD_SET_GAME_SESSION_CHECK_RES", "CMD_GET_GAME_SESSION_CHECK_RES",
    "CMD_GET_GAME_ID", "CMD_START_GAME", "CMD_SET_GAME_RESULT",
    "CMD_GET_GAME_RESULT", "CMD_ADD_SCORE", "CMD_ADD_FOUL",
}


def main():
    if not os.path.exists(FINAL):
        print("missing %s" % FINAL)
        return 1
    blocks = df.parse(FINAL)
    print("parsed %d gate blocks from the real capture\n" % len(blocks))

    argv = sys.argv[1:]
    if "--names" in argv:
        print("real client's gate sequence in order (%d blocks):\n"
              % len(blocks))
        for n, b in enumerate(blocks, 1):
            print("%3d. %-38s status=%s" % (n, b["cmd"] or "(non-gate)",
                                            b["status"]))
        return 0

    want = None
    if "--cmd" in argv:
        i = argv.index("--cmd")
        if i + 1 < len(argv):
            want = argv[i + 1].upper()
            if not want.startswith("CMD_"):
                want = "CMD_" + want
    elif "--key" not in argv:
        want = None

    for n, b in enumerate(blocks, 1):
        if want and b["cmd"] != want:
            continue
        if not want and "--key" in argv and b["cmd"] not in KEY:
            continue
        print("=" * 72)
        print("%3d. %s   status=%s" % (n, b["cmd"] or b["path"], b["status"]))
        rq, rqerr = df.decode(b["req_hex"])
        if rqerr:
            print("     REQUEST  : %s" % rqerr)
        else:
            print("     REQUEST")
            print(df.emit(rq))
        rs, rserr = df.decode(b["resp_hex"])
        if rserr:
            print("     RESPONSE : %s" % rserr)
        else:
            print("     RESPONSE")
            print(df.emit(rs))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
