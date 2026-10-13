#!/usr/bin/env python3
"""grpc_paths2.py -- list /Service/Method literals NOT UE4 asset paths."""
import re

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()

pat = re.compile(rb"/[A-Za-z][A-Za-z0-9_.]{1,40}/[A-Za-z][A-Za-z0-9_.]{2,60}")
skip = ("/Game/", "/Engine/", "/Script/", "/CharacterAssets/", "/Music/",
        "/Sound/", "/Movie/", "/Movies/", "/UI/", "/L10N/", "/Texture/",
        "/StaticMeshes/", "/SkeletalMeshes/", "/Map/", "/Maps/", "/Font/",
        "/Ar/", "/Face/", "/Hair/", "/Eyebrow/", "/Studio/")
seen = set()
for m in pat.finditer(data):
    s = m.group().decode(errors="replace")
    if s.startswith(skip) or s in seen:
        continue
    seen.add(s)
# also require NUL right after (real literals)
real = []
for s in sorted(seen):
    i = data.find(s.encode() + b"\x00")
    if i >= 0:
        real.append((i, s))
print("non-asset method-like literals (NUL-terminated): %d" % len(real))
for i, s in real[:150]:
    print("  0x%x  %s" % (i, s))
