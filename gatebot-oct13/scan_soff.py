#!/usr/bin/env python3
"""scan_soff.py -- find SIMD single FP STR s-reg,[x-reg,#imm] for chosen byte offsets.

  python scan_soff.py 0x168 0x16c 0x170 [lo_ghidra hi_ghidra]
Prints Ghidra addresses (vaddr + 0x100000).
"""
import struct
import sys
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
offs = [int(a, 16) for a in sys.argv[1:5] if a.startswith("0x")]
rest = [a for a in sys.argv[1:] if not a.startswith("0x")]
lo = int(rest[0], 16) - GHI if len(rest) > 0 else 0
hi = int(rest[1], 16) - GHI if len(rest) > 1 else 0xFFFFFFFF
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
want = {o >> 2 for o in offs}
hits = []
for i in range(0, len(text) - 4, 4):
    pc = tv + i
    if pc < lo or pc > hi:
        continue
    w = struct.unpack_from("<I", text, i)[0]
    if w & 0xFFC00000 != 0xBD000000:   # str st,[xn,#imm12] (scale 4)
        continue
    imm = (w >> 10) & 0xFFF
    if imm in want:
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        hits.append("0x%08x  str s%d, [x%d, #0x%x]" % (pc + GHI, rt, rn, imm * 4))
print("hits:", len(hits))
print("\n".join(hits))
