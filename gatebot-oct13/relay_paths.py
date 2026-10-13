#!/usr/bin/env python3
"""relay_paths.py -- find cobra/NatTraversal source-path literals mentioning
relay/gamerelay/turn in libUE4.so.

Assert/log strings carry full source paths (proven: the repo quotes
'cobra/NatTraversal/NTL/ntl/NtlHelper.cpp').  Those ARE normal C-string
literals with adrp+add xrefs -- they anchor us inside the relay client
code, from where we can walk to the connect/framing logic.

  python relay_paths.py
"""
import re

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()

# path-like tokens with a source extension
pat = re.compile(rb"[A-Za-z0-9_./\\-]{6,140}\.(?:cpp|h|c|cc)\x00")
hits = {}
for m in pat.finditer(data):
    s = m.group().decode(errors="replace")
    low = s.lower()
    for kw in ("relay", "turn", "ntl", "nat", "session", "match",
               "cobra", "pesms", "grpc", "socket"):
        if kw in low:
            hits.setdefault(kw, [])
            if s not in hits[kw]:
                hits[kw].append(s)

for kw in sorted(hits):
    print("\n%s (%d):" % (kw, len(hits[kw])))
    for p in hits[kw][:22]:
        print("  %s" % p)
