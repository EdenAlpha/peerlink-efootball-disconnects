#!/usr/bin/env python3
"""callers2.py -- who calls the per-command WRAPPERS (level-2 trace),
and extract those bodies too.  This walks up to the state machine that
sequences the post-room flow."""
import os
import re
import sys

D = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr"
FILES = ["punch", "natwire", "rp_dispatch"]
MAIN = os.path.join(D, "fulldump2_out.txt")

LEVEL1 = ["07eaeaa8", "07ead038", "07eadd8c", "07eb10e0",
          "07e5b638", "07e46054", "07e2b4e4",
          "077e0c7c", "077e4774", "077e835c", "07729884",
          "07726938", "07721a3c"]

pat = re.compile(rb"FUN_(%s)\s*\(" % b"|".join(w.encode() for w in LEVEL1))
hits = {}
cur_file = {}
for tag in FILES + ["main"]:
    path = (os.path.join(D, tag, "fulldump2_out.txt") if tag != "main"
            else MAIN)
    sys.stderr.write("scan %s ...\n" % tag)
    cur = None
    with open(path, "rb") as f:
        for line in f:
            if line.startswith(b"==== "):
                cur = line.split()[1].decode()
            elif cur is not None:
                for m in pat.finditer(line):
                    tgt = m.group(1).decode()
                    if cur != tgt:
                        hits.setdefault(tgt, set()).add((tag, cur))

lines = []
for tgt in sorted(hits):
    lines.append("== wrapper %s called by:" % tgt)
    for tag, fn in sorted(hits[tgt]):
        lines.append("   %s [%s]" % (fn, tag))
dst = os.path.join(D, "..", "flow_callers2.txt")
open(dst, "w", encoding="utf-8").write("\n".join(lines))
print("\n".join(lines))
