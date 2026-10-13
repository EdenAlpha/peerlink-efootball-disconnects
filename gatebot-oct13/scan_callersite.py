#!/usr/bin/env python3
"""scan_callersite.py -- for each BL to a target, scan forward N insns for given ldr32 offsets / add imms.

  python scan_callersite.py 07f0afcc 60 0x78 0x7c 0x80 0x84 [adds:0x6a0]
Prints Ghidra addresses of the call and the matching instructions.
"""
import struct, sys
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
tgt_g = int(sys.argv[1], 16)
n_ins = int(sys.argv[2])
rest = sys.argv[3:]
ldrs, adds = set(), set()
for a in rest:
    if a.startswith("add:"):
        adds.add(int(a[4:], 16))
    else:
        ldrs.add(int(a, 16))

e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
n = len(text) // 4
out = []
for i in range(n):
    w = struct.unpack_from("<I", text, i * 4)[0]
    if w & 0xFC000000 != 0x94000000:
        continue
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    if tv + i * 4 + (imm << 2) + GHI != tgt_g:
        continue
    found = []
    for j in range(i + 1, min(i + 1 + n_ins, n)):
        w2 = struct.unpack_from("<I", text, j * 4)[0]
        pc = tv + j * 4 + GHI
        if w2 & 0xFFC00000 == 0xB9400000:            # ldr32 [xn,#imm12]
            o = ((w2 >> 10) & 0xFFF) * 4
            if o in ldrs:
                found.append("0x%08x ldr32 #0x%x" % (pc, o))
        elif w2 & 0xFFC00000 == 0x91000000:           # add xd,xn,#imm12
            o = ((w2 >> 10) & 0xFFF) * (4096 if w2 & (1 << 22) else 1)
            if o in adds:
                found.append("0x%08x add #0x%x" % (pc, o))
    if found:
        out.append((tv + i * 4 + GHI, found))
for pc, f in out:
    print("call 0x%08x :" % pc)
    for s in f:
        print("    " + s)
print("callers_with_hits: %d" % len(out))
