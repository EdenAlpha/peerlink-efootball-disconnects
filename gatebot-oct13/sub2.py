import os, sys
D = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr"
WANT = ["077240d4"]
def blocks(path):
    cur, buf = None, []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("==== "):
                if cur is not None: yield cur, "".join(buf)
                cur = line.split()[1]; buf = [line]
            elif cur is not None: buf.append(line)
    if cur is not None: yield cur, "".join(buf)
out = []
for tag in ["punch","natwire","rp_dispatch"]:
    for addr, text in blocks(os.path.join(D, tag, "fulldump2_out.txt")):
        if addr in WANT:
            out.append(text); WANT.remove(addr)
    if not WANT: break
open(os.path.join(D, "..", "flow_sub2.txt"), "w", encoding="utf-8").write("".join(out))
print("found:", "all" if not WANT else WANT)
