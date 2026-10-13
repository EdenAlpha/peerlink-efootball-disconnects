import re, os, collections
D = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr\full1110"
scan = open(r"C:\Users\Administrator\Documents\Default Project\work\fsm_scan.txt", encoding="utf-8", errors="replace").read()
straddrs = set()
for line in scan.splitlines():
    parts = line.split()
    if len(parts) < 2: continue
    for a in parts[1:]:
        if re.fullmatch(r"[0-9a-f]{8}", a):
            straddrs.add(a)
print("string addrs:", len(straddrs))
xref = collections.defaultdict(set)
with open(os.path.join(D, "fulldump_out.txt"), encoding="utf-8", errors="replace") as f:
    for line in f:
        if "REF" not in line: continue
        toks = re.findall(r"\b[0-9a-f]{8}\b", line)
        if len(toks) >= 2 and toks[0] in straddrs:
            xref[toks[1]].add(toks[0])
        elif len(toks) >= 2 and toks[1] in straddrs:
            xref[toks[0]].add(toks[1])
print("referencing funcs:", len(xref))
for fn in sorted(xref, key=lambda k: -len(xref[k]))[:20]:
    print("%s  refs=%d" % (fn, len(xref[fn])))
