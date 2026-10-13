#!/usr/bin/env python3
"""scan_cluster.py -- find functions containing >=N distinct 32-bit ldr offsets in a set.

  python scan_cluster.py 0x78 0x7c 0x80 0x84 [min_hits] [window]
Prints Ghidra addresses; clusters hits within `window` bytes.
"""
import struct, sys, collections
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
argv = sys.argv[1:]
offs = []
while argv and argv[0].startswith("0x"):
    offs.append(int(argv.pop(0), 16))
min_hits = int(argv[0]) if argv else 3
window = int(argv[1], 16) if len(argv) > 1 else 0x200

e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
sites = collections.defaultdict(list)
for i in range(0, len(text) - 4, 4):
    w = struct.unpack_from("<I", text, i)[0]
    if w & 0xFFC00000 != 0xB9400000:      # ldr wt,[xn,#imm12]
        continue
    imm = ((w >> 10) & 0xFFF) * 4
    if imm in offs:
        sites[imm].append(tv + i)

# cluster: slide over sorted pcs
allp = sorted(p for v in sites.values() for p in v)
groups = []
cur = []
for p in allp:
    if cur and p - cur[-1] > window:
        groups.append(cur); cur = []
    cur.append(p)
if cur:
    groups.append(cur)
n = 0
for g in groups:
    gs = set(g)
    offs_present = sorted({imm for imm, v in sites.items() for p in v if p in gs})
    if len(offs_present) >= min_hits:
        n += 1
        print("0x%08x..0x%08x  distinct_offs=%d %s"
              % (g[0] + GHI, g[-1] + GHI, len(offs_present),
                 " ".join("#0x%x" % o for o in offs_present)))
print("groups:", n)
