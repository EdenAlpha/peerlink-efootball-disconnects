#!/usr/bin/env python3
"""scan_cfg6a0.py -- find `add xd,xn,#0x6a0` followed within 5 insns by
ldr w?,[xd,#0x78|#0x7c|#0x80|#0x84]. Prints Ghidra addresses."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
n = len(text)
LDRS = {0x78: 0x1E, 0x7C: 0x1F, 0x80: 0x20, 0x84: 0x21}
for i in range(0, n - 24, 4):
    w = struct.unpack_from("<I", text, i)[0]
    # add xd, xn, #0x6a0 (64-bit, sh=0)
    if w & 0xFFC00000 != 0x91000000:
        continue
    if ((w >> 10) & 0xFFF) != 0x6A0:
        continue
    rd = w & 0x1F
    addpc = tv + i
    for k in range(4, 24, 4):
        if i + k >= n:
            break
        w2 = struct.unpack_from("<I", text, i + k)[0]
        if w2 & 0xFFC00000 != 0xB9400000:   # ldr wt,[xn,#imm12]
            continue
        imm = (w2 >> 10) & 0xFFF
        rn = (w2 >> 5) & 0x1F
        if rn == rd and imm in LDRS.values():
            rt = w2 & 0x1F
            print("0x%08x  add x%d,#0x6a0 ; then 0x%08x ldr w%d,[x%d,#0x%x]"
                  % (addpc + GHI, rd, tv + i + k + GHI, rt, rn, imm * 4))
            break
