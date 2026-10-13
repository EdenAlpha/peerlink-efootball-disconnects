#!/usr/bin/env python3
"""scan_adpage.py -- list every adrp resolving to a page and the ldr/str imm used on it.

  python scan_adpage.py 0xa5d9000
"""
import struct, sys
from xref2 import Elf, adrpf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
page = int(sys.argv[1], 16)
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
n = len(text) // 4
hits = 0
for i in range(n):
    w = struct.unpack_from("<I", text, i * 4)[0]
    rd, delta = adrpf(w)
    if rd is None:
        continue
    pc = tv + i * 4
    if (pc & ~0xFFF) + delta != page:
        continue
    # collect loads/stores on rd in next 8 insns
    ops = []
    for j in range(i + 1, min(i + 9, n)):
        w2 = struct.unpack_from("<I", text, j * 4)[0]
        rn = (w2 >> 5) & 0x1F
        if rn != rd:
            continue
        if w2 & 0xFFC00000 == 0xF9400000:
            ops.append("ldr #0x%x" % (((w2 >> 10) & 0xFFF) * 8))
        elif w2 & 0xFFC00000 == 0xF9000000:
            ops.append("str #0x%x" % (((w2 >> 10) & 0xFFF) * 8))
        elif w2 & 0xFFC00000 == 0xB9400000:
            ops.append("ldr32 #0x%x" % (((w2 >> 10) & 0xFFF) * 4))
        elif w2 & 0xFFC00000 == 0xB9000000:
            ops.append("str32 #0x%x" % (((w2 >> 10) & 0xFFF) * 4))
        elif w2 & 0xFFC00000 == 0x91000000:
            ops.append("add #%d" % (((w2 >> 10) & 0xFFF) * (4096 if w2 & (1 << 22) else 1)))
    print("0x%08x  %s" % (pc + GHI, ", ".join(ops) or "-"))
    hits += 1
print("hits:", hits)
