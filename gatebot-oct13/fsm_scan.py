import re, os
D = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr"
# find every function that references the flow-state strings in the 11.1.0 STR section
needles = ["MODE_SESSION","MODE_CONNECT","MODE_ANNTENA","MODE_PRE_MENU",
           "SESSION_ESTABLISH","NTL_PUNCHING","NTL_STUNCHECK","WAIT_SOCKET",
           "CONNECT_SESSION","REVISION_CHECK","QUALITY_TEST","USER_DATA_SYNC",
           "TEAM_DATA_SYNC","READY_ALL_PLAYER","DISP_MATCHING_RESULT",
           "MODE_MATCHING","WAIT_QUALITY","TURN_CONNECT","RESOLVING_NAME",
           "CONNECT_UDP","CONNECT_PEER","NTL_PUNCHING_PRE","NTL_PUNCHING_PROCESS",
           "NTL_PUNCHING_RETRY","NTL_PUNCHING_PROCESS_ON_SUCCESS"]
strpath = os.path.join(D, "full1110", "fulldump_out.txt")
pat = re.compile(r"^STR ([0-9a-f]+) (.+?) \|(.+)$")
hits = {}
with open(strpath, encoding="utf-8", errors="replace") as f:
    for line in f:
        if not line.startswith("STR "):
            if hits and line[:4] not in ("STR ","SYM ","FUN ","DAT ","REF ","FUN"):
                pass
            continue
        m = pat.match(line)
        if not m: continue
        name = m.group(2).strip()
        if not any(n in name for n in needles): continue
        refs = m.group(3)
        for r in refs.split("|"):
            r = r.strip()
            if not r: continue
            addr = r.split("@")[0]
            if addr.startswith("07") or addr.startswith("08"):
                hits.setdefault(name, set()).add(addr)
for name in sorted(hits):
    print("%-42s %s" % (name, " ".join(sorted(hits[name]))))
