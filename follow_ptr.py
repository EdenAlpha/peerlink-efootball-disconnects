#!/usr/bin/env python3
"""Follow the request-object pointers in the live-stack region.

The 8MB region f501633fd000 holds SendRequest-style objects:
  sign=<cookie>;  cookie  = sign=...;  ...  isPost  = true  https
  pes22-game.cs.konami.net  /p...  + nearby 8-byte little-endian values.

Those 8-byte values are guest virtual addresses (0x7xxx/0xf5xx/0xf6xx range):
pointers to the URI string, the body buffer, and possibly the cipher context.
This script:
 1. extracts every 8-byte LE value near sign=/uri=/cookie= hits in the region,
 2. keeps those that fall inside a known mapped range (from maps.txt),
 3. reports which region each points into, so the target can be pulled fully.
"""
import re
import struct
import sys

ART = sys.argv[1] if len(sys.argv) > 1 else \
    r"C:\Users\Administrator\AppData\Local\Temp\2\artj\kgs-gappslive-36963768970\kgs\full"
FULL = ART + r"\full.bin"

# guest base of the live-stack region in THIS boot (pid 6597):
# region f501633fd000-f50163bfe000 @ fileoff 5288608
REG_FILEOFF = 5288608

f = open(FULL, "rb")
f.seek(REG_FILEOFF)
reg = f.read(0x810000)
print("region bytes: %d" % len(reg))

# candidate pointers: 8-byte LE values in a plausible guest range
cands = {}
for m in re.finditer(b"sign=", reg):
    base = max(0, m.start() - 64)
    win = reg[base:m.start() + 256]
    for i in range(0, len(win) - 8):
        v = struct.unpack("<Q", win[i:i + 8])[0]
        # ART heap / native heap guest range seen in maps: 0x12c00000..0xf7...
        if 0x10000000 <= v <= 0xFFFFFFFFFFFF:
            # must be 8-aligned-ish and not ASCII text itself
            cands.setdefault(v, []).append(m.start())

print("distinct pointer-shaped values near sign=: %d" % len(cands))
top = sorted(cands.items(), key=lambda kv: -len(kv[1]))[:25]
for v, uses in top:
    print("  0x%012x refs=%d" % (v, len(uses)))

# load maps to resolve
print()
print("resolving against maps.txt ...")
rngs = []
# maps from the SAME boot (pid 6597, KU dump), not the post-restart snap:
# ASLR re-randomizes every boot, so only same-boot maps resolve these pointers.
for line in open(ART + r"\maps.txt", errors="replace"):
    p = line.split()
    if len(p) < 5 or "-" not in p[0]:
        continue
    s, e = p[0].split("-")
    try:
        rngs.append((int(s, 16), int(e, 16), p[1], p[4 - 4 + 4][:60] if len(p) > 4 else ""))
    except ValueError:
        continue


def where(v):
    for (s, e, pm, nm) in rngs:
        if s <= v < e:
            return "%x-%x %s %s" % (s, e, pm, nm)
    return "UNMAPPED"


print("maps ranges: %d" % len(rngs))
for v, uses in top:
    print("  0x%012x refs=%d -> %s" % (v, len(uses), where(v)))
