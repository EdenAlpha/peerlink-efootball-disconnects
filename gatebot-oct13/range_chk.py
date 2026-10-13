import re
p = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr\fulldump2_out.txt"
lo = hi = None
with open(p, encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.startswith("==== "):
            a = int(line.split()[1], 16)
            if lo is None or a < lo: lo = a
            if hi is None or a > hi: hi = a
print("main fulldump2 decomp range: %08x - %08x" % (lo, hi))
