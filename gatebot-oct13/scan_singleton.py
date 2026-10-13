#!/usr/bin/env python3
"""scan_singleton.py -- find adrp->page X then ldr imm, listing each site.

  python scan_singleton.py 0xa5d9d50
Prints Ghidra addresses of the adrp and the ldr that follows within 12 insns.
"""
import struct, sys
from xref2 import Elf, adrpf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000

target = int(sys.argv[1], 16)
page = target & ~0xFFF
off = target & 0xFFF

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
    # look ahead for ldr xt,[xn,#off]
    for j in range(i + 1, min(i + 16, n)):
        w2 = struct.unpack_from("<I", text, j * 4)[0]
        if w2 & 0xFFC00000 == 0xF9400000:          # ldr xt,[xn,#imm12]
            imm = ((w2 >> 10) & 0xFFF) * 8
            rn = (w2 >> 5) & 0x1F
            rt = w2 & 0x1F
            if rn == rd and imm == off:
                print("adrp 0x%08x -> ldr x%d,[x%d,#0x%x] @ 0x%08x"
                      % (pc + GHI, rt, rn, off, tv + j * 4 + GHI))
                hits += 1
                break
print("hits:", hits)
