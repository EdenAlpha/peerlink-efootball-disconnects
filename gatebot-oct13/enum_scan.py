#!/usr/bin/env python3
"""enum_scan.py -- list UPPER-case enum-ish strings by keyword.

Scans libUE4.so rodata for ALL-CAPS tokens containing a keyword
(DISCONN, NORMAL, ...) -- the intern pool holds every enum literal, so
this enumerates the legal vocabularies without field context.
"""
import re

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

KEYWORDS = ("DISCONN", "NORMAL", "TIMEOUT", "GIVEUP", "FORFEIT",
            "ABNORMAL", "GAMEEND", "GAME_RES", "REASON")

data = open(SO, "rb").read()
cands = {}
for m in re.finditer(rb"[ -~]{3,28}", data):
    s = m.group().decode()
    if s != s.upper():
        continue
    up = s
    for kw in KEYWORDS:
        if kw in up:
            cands.setdefault(kw, [])
            if s not in cands[kw]:
                cands[kw].append(s)

for kw in sorted(cands):
    print("%s (%d): %s" % (kw, len(cands[kw]), cands[kw][:40]))
