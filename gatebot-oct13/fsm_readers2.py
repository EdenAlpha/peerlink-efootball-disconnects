import re, collections
pat = re.compile(r"^STR [0-9a-f]+ (\S+) \|(.*?)\s*$")
readers = collections.defaultdict(set)
with open(r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr\full1110\fulldump_out.txt", encoding="utf-8", errors="replace") as f:
    for line in f:
        if not line.startswith("STR "): continue
        m = pat.match(line.rstrip())
        if not m: continue
        for r in m.group(2).split("|"):
            r = r.strip()
            am = re.match(r"([0-9a-f]+)@(FUN_[0-9a-f]+)", r)
            if am: readers[am.group(2)].add(m.group(1))
for fn in ("FUN_07f34644", "FUN_07f26c50"):
    print("==", fn)
    for lb in sorted(readers[fn]): print("  ", lb)
