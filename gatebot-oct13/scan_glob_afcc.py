#!/usr/bin/env python3
"""scan_glob_afcc.py -- find adrp #0xa5d9000 + ldr/str [x?,#0xd50] (singleton
slot) in .text; print Ghidra addrs and direction."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
PAGE = 0xa5d9000
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
n = len(text)
page = {}
for i in range(0, n - 8, 4):
    w = struct.unpack_from("<I", text, i)[0]
    if w & 0x9F000000 == 0x90000000:            # adrp
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page[rd] = ((tv + i) & ~0xFFF) + (imm << 12)
        continue
    # ldr/str x, [xn, #0xd50]  (unsigned 64-bit, imm12 = 0x1ac)
    if w & 0xFFC00000 not in (0xF9400000, 0xF9000000):
        continue
    if ((w >> 10) & 0xFFF) != 0x1AA:
        continue
    rn = (w >> 5) & 0x1F
    if page.get(rn) != PAGE:
        continue
    rt = w & 0x1F
    kind = "ldr" if (w >> 22) & 1 else "str"
    print("0x%08x  %s x%d, [x%d, #0xd50]" % (tv + i + GHI, kind, rt, rn))
