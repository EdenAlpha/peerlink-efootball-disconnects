#!/usr/bin/env python3
"""enum_values.py -- enumerate an enum's values via its UE4 TYPE::VALUE strings.

UE4 registers enum literals as 'TYPE::VALUE'.  Find every string starting
with a given type name and print the value list.

  python enum_values.py ABNORMALEND_REASON
  python enum_values.py GAMEEND_REASON
"""
import re
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()

types = sys.argv[1:] or ["ABNORMALEND_REASON", "GAMEEND_REASON",
                         "GAME_RES", "ERROR_CODE"]
for t in types:
    pat = (t + "::").encode()
    vals = []
    for m in re.finditer(re.escape(pat) + rb"[ -~]{1,28}", data):
        s = m.group().decode()
        vals.append(s.split("::", 1)[1])
    seen = []
    for v in vals:
        if v not in seen:
            seen.append(v)
    print("%s:: (%d) %s" % (t, len(seen), seen))
