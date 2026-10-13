#!/usr/bin/env python3
"""scan_toff.py -- find 32-bit LDR w-reg,[x-reg,#imm] for chosen byte offsets.

  python scan_toff.py 0x718 0x71c 0x720 0x724 [lo_ghidra hi_ghidra]
Prints Ghidra addresses (vaddr + 0x100000).
"""
import struct
import sys
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
offs = [int(a, 16) for a in sys.argv[1:5]]
lo = int(sys.argv[5], 16) - GHI if len(sys.argv) > 5 else 0
hi = int(sys.argv[6], 16) - GHI if len(sys.argv) > 6 else 0xFFFFFFFF
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
want = {}
for o in offs:
    want.setdefault(o >> 2, []).append(o)
n = len(text)
for i in range(0, n - 4, 4):
    pc = tv + i
    if pc < lo or pc > hi:
        continue
    w = struct.unpack_from("<I", text, i)[0]
    if w & 0xFFC00000 != 0xB9400000:   # ldr wt,[xn,#imm12] 32-bit
        continue
    imm = (w >> 10) & 0xFFF
    if imm in want:
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        print("0x%08x  ldr w%d, [x%d, #0x%x]" % (pc + GHI, rt, rn, imm * 4))
