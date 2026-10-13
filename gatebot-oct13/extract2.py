import os, sys
D = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr"
FILES = ["punch", "natwire", "rp_dispatch"]
MAIN = os.path.join(D, "fulldump2_out.txt")
WANT = ["07ec7164","07e442a8","07e2bf1c","07e5b638","07e46054","07e2b4e4",
        "07eaeaa8","07ead038","07eadd8c","07eb10e0",
        "077e0c7c","077e4774","077e835c","07729884","07726938"]
def blocks(path):
    cur, buf = None, []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("==== "):
                if cur is not None: yield cur, "".join(buf)
                cur = line.split()[1]; buf = [line]
            elif cur is not None: buf.append(line)
    if cur is not None: yield cur, "".join(buf)
found = {}
for tag in FILES:
    for addr, text in blocks(os.path.join(D, tag, "fulldump2_out.txt")):
        if addr in WANT and addr not in found: found[addr] = (tag, text)
miss = [a for a in WANT if a not in found]
if miss:
    for addr, text in blocks(MAIN):
        if addr in miss:
            found[addr] = ("main", text); miss.remove(addr)
        if not miss: break
out = []
for a in WANT:
    if a in found:
        tag, text = found[a]
        out.append("\n########## from=%s ##########\n" % tag); out.append(text)
    else:
        out.append("\n########## %s NOT FOUND ##########\n" % a)
dst = os.path.join(D, "..", "flow_decomp2.txt")
open(dst, "w", encoding="utf-8").write("".join(out))
print("extracted %d/%d -> %s (%.1f MB)" % (len(found), len(WANT), dst, os.path.getsize(dst)/1e6))
