#!/usr/bin/env python3
"""scan_addrtaken.py -- find adrp+add computing a given Ghidra address (address-taken).

  python scan_addrtaken.py 07f0afcc
"""
import struct, sys
from xref2 import Elf, adrpf, addimm

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
t = int(sys.argv[1], 16) - GHI          # vaddr target
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
    if (pc & ~0xFFF) + delta > t:
        continue
    for j in range(i + 1, min(i + 6, n)):
        w2 = struct.unpack_from("<I", text, j * 4)[0]
        a = addimm(w2)
        if a and a[1] == rd and (pc & ~0xFFF) + delta + a[2] == t:
            print("adrp+add -> 0x%08x : adrp@0x%08x add@0x%08x"
                  % (t + GHI, pc + GHI, tv + j * 4 + GHI))
            hits += 1
            break
print("hits:", hits)
