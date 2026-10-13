#!/usr/bin/env python3
"""grpc_paths.py -- find gRPC method paths and relay identifiers.

The relay control plane answered like gRPC (HTTP/2 over TLS).  gRPC
clients embed '/package.Service/Method' literals.  Scanning libUE4.so
for those + 'pesms' + relay-ish tokens yields the exact RPC surface the
bot must speak to join the relay session.
"""
import re

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()

pats = [
    rb"/[A-Za-z][A-Za-z0-9_.]{2,30}/[A-Za-z][A-Za-z0-9_.]{2,40}",
    rb"[ -~]{0,24}pesms[ -~]{0,40}",
    rb"[ -~]{0,16}[Rr]elay[A-Za-z_]{0,24}[ -~]{0,16}",
]
seen = set()
for pat in pats:
    for m in re.finditer(pat, data):
        s = m.group().decode(errors="replace")
        if s in seen or len(s) < 5:
            continue
        seen.add(s)
print("gRPC-style paths (unique): %d" % len(seen))
paths = sorted(p for p in seen if p.startswith("/"))
for p in paths[:120]:
    print("  %s" % p)
rest = sorted(p for p in seen if not p.startswith("/"))
print("\npesms/relay tokens (%d):" % len(rest))
for p in rest[:80]:
    print("  %s" % p)
