#!/usr/bin/env python3
"""sgr_keys.py -- extract annotated STR strings (in order) from sgr_enc.dis
and cross-check against the chain3.py sgr_request body keys."""
import re

p = (r"C:\Users\Administrator\Documents\Default Project\work\sgr_enc.dis")
keys = []
for line in open(p, encoding="utf-8", errors="replace"):
    m = re.search(r"; STR \S+ '([^']*)'", line)
    if m:
        keys.append(m.group(1))
print(len(keys), "annotated strings")
for i, k in enumerate(keys):
    print("%3d  %s" % (i, k))
