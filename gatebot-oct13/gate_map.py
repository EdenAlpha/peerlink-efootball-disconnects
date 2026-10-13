#!/usr/bin/env python3
"""gate_map.py -- derive the authoritative CMD_ -> Cmd*.php endpoint map.

Every gate command's descriptor builder references BOTH its `CMD_` name and its
`CmdXxx.php` route from the same function (verified on CMD_SET_GAME_RESULT:
FUN_078a0f7c touches 'CMD_SET_GAME_RESULT' and 'CmdSetGameResult.php').
Internal, non-gate signals (CMD_READY_FLAG, CMD_ALIGN_PROGRESS,
CMD_REVISION_CHECK) reference the CMD_ name but NO .php.

So: group the STR xrefs by function, and a function naming a CMD_ *and* a
.Cmd*.php is a real gate command.  This settles "is it a gate command?" for
all 412 CMD_ names at once, instead of one 6-minute chain run each.

Read-only.  Run:  python gate_map.py
"""
import re
import sys

DUMP = (r"C:\Users\Administrator\Documents\Default Project\work"
        r"\ghidra_sgr\full1110\fulldump_out.txt")
CHAIN3 = (r"C:\Users\Administrator\Documents\Default Project\work"
          r"\chain3.py")

STR_RE = re.compile(r"^STR ([0-9a-f]{8}) (.*?)(?: \|(.*)|$)")
XREF_RE = re.compile(r"([0-9a-f]{8})@(\S+)")


def main():
    func_cmds = {}     # func -> set of CMD_ names
    func_phps = {}     # func -> set of Cmd*.php names
    cmd_funcs = {}     # CMD_ name -> set of funcs

    with open(DUMP, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("STR "):
                continue
            m = STR_RE.match(line.rstrip("\n"))
            if not m:
                continue
            name = m.group(2).strip()
            xrefs = m.group(3) or ""
            funcs = {fn for _, fn in XREF_RE.findall(xrefs)
                     if fn.startswith("FUN_")}
            if not funcs:
                continue
            if name.startswith("CMD_") and re.fullmatch(r"CMD_[A-Z0-9_]+", name):
                cmd_funcs.setdefault(name, set()).update(funcs)
                for fn in funcs:
                    func_cmds.setdefault(fn, set()).add(name)
            elif name.startswith("Cmd") and name.endswith(".php"):
                for fn in funcs:
                    func_phps.setdefault(fn, set()).add(name)

    # CMD_ -> php where some single function names both
    mapping = {}
    for fn, cmds in func_cmds.items():
        for php in func_phps.get(fn, ()):
            for c in cmds:
                mapping.setdefault(c, set()).add(php)

    # what chain3 sends
    have = set()
    with open(CHAIN3, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            have.update(re.findall(r'envelope\("([A-Z_]+)"\)', line))

    print("CMD_ names in binary      : %d" % len(cmd_funcs))
    print("resolved as GATE commands : %d" % len(mapping))
    print("chain3.py sends           : %d" % len(have))
    print()

    resolved = set(mapping)
    print("=== chain3 sends but NOT resolved to a .php (check!) ===")
    for c in sorted(have - resolved):
        print("  %s" % c)
    print()

    print("=== GATE commands chain3 does NOT send (match-flow subset) ===")
    skip = ("BUY_", "GET_MYCLUB", "SET_MYCLUB", "ML_EVENT", "SEASON_",
            "COMMUNITY", "FRIEND", "EVENT_", "KID_", "KONAMIID",
            "ADULT", "CAMPAIGN", "SUGOROKU", "STRIKE", "FAME",
            "PATHTOGLORY", "MARKET", "SCOUT", "PACK", "AGENT", "BINGO",
            "AUTH_", "BIND_", "REQUEST_", "ACCOUNT", "PROMOTION", "MAILBOX",
            "RANKING", "COIN_", "ASSET", "SHOP", "SURVEY", "VOTING",
            "LEAGUE", "COMMENTARY", "STADIUM", "ADVERTISEMENT", "LIVE",
            "GUEST", "DELETE_", "RESET_", "RESTORE_", "SAVE_", "VERIFY_",
            "SEND_REDEEM", "SEND_RECRUIT", "SEND_FRIEND", "SEND_ML",
            "ACCEPT_", "APPROVE_", "CANCEL_FRIEND", "INVITE_", "JOIN_INVITED",
            "KICK_", "LEAVE_COMMUNITY", "REPAIR_", "SHARE_", "TRANSFER_",
            "UPDATE_COMMUNITY", "UPDATE_TERMS", "UNLOCK_", "USE_MYCLUB",
            "CREATE_MYCLUB", "DELETE_MYCLUB", "SWITCH_MYCLUB", "INHERIT_",
            "RECV_", "PROGRESS_MYCLUB", "IS_FIRST", "INTERSECTION",
            "SEARCH_USER", "SEND_VOICE", "WATCH_VOICE", "WATCH_INVIT",
            "WATCH_NOTICE", "SEND_NOTICE", "DEMOCHAT", "SEND_REPORT",
            "GET_IS_", "GET_KID", "GET_KONAMI", "GET_ADULT", "GET_EULA",
            "GET_USER_EULA", "GET_COUNTRY", "GET_LOCALIZED", "GET_MAILBOX",
            "GET_MAINMENU", "GET_PRODUCT", "GET_STORE", "GET_PROMOTION",
            "GET_PSN", "GET_PLATFORM", "GET_VOID", "GET_MUTE", "GET_BLOCK",
            "GET_BALANCE", "GET_COMMENT", "GET_STADIUM", "GET_EXCHANGE",
            "GET_RECRUIT", "GET_CAMPAIGN", "GET_BIG_DATA", "GET_ANALYST",
            "GET_AVATAR", "GET_AGE_GATE", "SET_ANALYST", "SET_AVATAR",
            "SET_BANNER", "SET_BLOCK", "SET_MUTE", "SET_LANGUAGE",
            "SET_LOCAL_GAMERELAY", "SET_CROSS_PLATFORM", "SET_EMOJI",
            "SET_NEWSLIST", "SET_OPT", "SET_PROMOTION", "SET_REWARD",
            "SET_TRACKRECORD", "SET_MENU_TRACKRECORD", "SET_USER_BANNER",
            "SET_USER_PROFILE", "SET_USER_DETAIL", "SET_USER_FAME",
            "SET_USER_EULA", "SET_COOP_TITLE", "SET_CMP", "SET_SUGOROKU",
            "SET_STRIKE", "SET_ONLINE_MINI", "SET_ONLINE_STATS",
            "FAILED_COUNT", "FINISHED_COUNT", "UNSUBSCRIBE", "RETRY_REC",
            "DEBUG_", "SEND_ADJUST", "SEND_ANALYSIS", "SEND_AUTH",
            "SEND_CAMPAIGN", "SEND_SESSION_FAILED", "SUCCESS_ADVERTISEMENT",
            "DATA_TRANSITION", "PLATFORM_SESSION", "CMD_[")
    for c in sorted(resolved - have):
        if any(c.startswith("CMD_" + p) or p in c for p in skip):
            continue
        print("  %-42s -> %s" % (c, ",".join(sorted(mapping[c]))))
    print()

    print("=== ALL resolved gate commands (CMD_ -> endpoint) ===")
    for c in sorted(mapping):
        print("  %-42s -> %s" % (c, ",".join(sorted(mapping[c]))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
