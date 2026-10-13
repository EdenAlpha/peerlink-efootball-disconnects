#!/usr/bin/env python3
"""flow_scan.py -- find EVERY function in the fulldump2 decomp dumps that
touches the post-room-creation flow (punch / TURN / relay / session /
start-game / phases / result), across all four region dumps.

Output: keyword -> {func_addr: [dumps]} so we can extract full decomp
bodies without missing anything.
"""
import os
import sys

D = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr"
FILES = {
    "main": os.path.join(D, "fulldump2_out.txt"),
    "punch": os.path.join(D, "punch", "fulldump2_out.txt"),
    "natwire": os.path.join(D, "natwire", "fulldump2_out.txt"),
    "rp": os.path.join(D, "rp_dispatch", "fulldump2_out.txt"),
}

# post-room-creation flow keywords (commands + body keys + concepts)
KEYS = [
    # gate commands in the room->match->result arc
    b"CMD_CREATE_ROOM", b"CMD_JOIN_ROOM", b"CMD_GET_ROOM_INFO",
    b"CMD_JOIN_REQUEST", b"CMD_READY", b"CMD_JOIN_GAME",
    b"CMD_GET_GAME_SESSION", b"CMD_SET_GAME_SESSION_CHECK_RES",
    b"CMD_GET_GAME_SESSION_CHECK_RES",
    b"CMD_GET_TURN_SERVER_LIST", b"CMD_GET_TURN_ADDRESS_DATA",
    b"CMD_SEND_TURN_ADDRESS_DATA", b"CMD_WATCH_TURN_ADDRESS_DATA",
    b"CMD_SET_LOCAL_GAMERELAY_LIST",
    b"CMD_GET_GAMERELAY_QUALITYCHECK_LIST", b"CMD_SET_GAMERELAY_QUALITY",
    b"CMD_GET_NAT_TYPE", b"CMD_START_GAME", b"CMD_RETURN_ROOM",
    b"CMD_CHANGE_GAMEPHASE", b"CMD_ADD_SCORE",
    b"CMD_SET_GAME_RESULT", b"CMD_CHECK_GAME_RESULT",
    b"CMD_GET_GAME_RESULT",
    # body keys / concepts of the punch+relay layer
    b"turn_account_param", b"turn_time_limit", b"turn_server_list",
    b"turn_account", b"address_data_size", b"ntl_address_list",
    b"nat_type", b"reflexive_address", b"reflexive_port",
    b"punch", b"address_data", b"relay_quality", b"qualitycheck",
]

hits = {}     # key -> {func_addr: set(dumps)}
cur_func = {}
for tag, path in FILES.items():
    sys.stderr.write("scanning %s ...\n" % tag)
    cur = None
    with open(path, "rb") as f:
        for line in f:
            if line.startswith(b"==== "):
                cur = line.split()[1].decode()
            elif cur and b"CMD_" in line or (cur and b"turn_" in line) \
                    or (cur and b"address" in line) \
                    or (cur and b"nat_type" in line) \
                    or (cur and b"relay" in line) \
                    or (cur and b"punch" in line) \
                    or (cur and b"reflexive" in line):
                for k in KEYS:
                    if k in line:
                        hits.setdefault(k, {}).setdefault(
                            cur, set()).add(tag)

out = []
for k in KEYS:
    m = hits.get(k, {})
    out.append("== %s : %d funcs" % (k.decode(), len(m)))
    for addr in sorted(m):
        out.append("   %s  [%s]" % (addr, ",".join(sorted(m[addr]))))
open(os.path.join(D, "..", "flow_map_funcs.txt"), "w",
     encoding="utf-8").write("\n".join(out))
print("\n".join(out))
