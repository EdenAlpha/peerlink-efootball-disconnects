#!/usr/bin/env python3
import re

p = r"C:\Users\Administrator\Documents\Default Project\work\sgr_enc.dis"
data = open(p, "rb").read()
i = data.find(b"STR ")
seg = data[i - 10: i + 60]
print(" ".join("%02x" % b for b in seg))
print(repr(seg))
print("match:", re.search(rb"; STR [0-9a-f]+ '([^']*)'", seg))
print("match2:", re.search(rb"STR [0-9a-f]+", seg))
print("match3:", re.search(rb"'([^']*)'", seg))
