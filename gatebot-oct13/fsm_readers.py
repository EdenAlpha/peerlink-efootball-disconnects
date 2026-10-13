import re, collections
pat = re.compile(r"^STR [0-9a-f]+ (LATENCY_MODE|LATENCY_NTL|LATENCY_SESSION|LATENCY_TURN|CMD_REVISION_CHECK|CMD_TEAM_DATA_SYNC|CMD_USER_DATA_SYNC)(\S*) \|(.*?)$")
readers = collections.defaultdict(set)   # func -> set of labels
labels = {}
with open(r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr\full1110\fulldump_out.txt", encoding="utf-8", errors="replace") as f:
    for line in f:
        if not line.startswith("STR ") or "LATENCY" not in line and "CMD_" not in line:
            continue
        m = pat.match(line.rstrip())
        if not m: continue
        name = m.group(1) + m.group(2)
        refs = m.group(3)
        for r in refs.split("|"):
            r = r.strip()
            if not r: continue
            am = re.match(r"([0-9a-f]+)@(FUN_[0-9a-f]+)", r)
            if am:
                readers[am.group(2)].add(name)
for fn in sorted(readers, key=lambda k: -len(readers[k]))[:25]:
    print("%s  labels=%d" % (fn, len(readers[fn])))
    if len(readers[fn]) >= 5:
        for lb in sorted(readers[fn])[:60]:
            print("    %s" % lb)
