#!/usr/bin/env python3
"""strategy_paths.py -- list every source-path literal under Multiplay /
SessionStrategy / Relay / NTL in libUE4.so.

The SC relay data-plane client lives in one of these files.  Once
identified, its file-path literal xrefs land us in the connect/framing
code.

  python strategy_paths.py
"""
import re

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()

pat = re.compile(rb"[A-Za-z0-9_./\\-]{6,180}\.(?:cpp|h|c|cc)\x00")
seen = set()
for m in pat.finditer(data):
    s = m.group().decode(errors="replace")
    if s in seen:
        continue
    seen.add(s)
    low = s.lower()
    if ("multiplay" in low or "sessionstrategy" in low
            or "natTraversal" in s or "/ntl" in low
            or "relay" in low or "serverclient" in low
            or "matchonline" in low):
        print("  %s" % s)
