#!/usr/bin/env python3
"""scan_get6a0.py -- find functions that return obj+0x6a0:
   add x0,x0,#0x6a0 ... ret   (small window)
Also prints any add #0x6a0 whose result is used as x0 for a bl within 8 insns."""
import struct
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
n = len(text)
for i in range(0, n - 32, 4):
    w = struct.unpack_from("<I", text, i)[0]
    if w & 0xFFC00000 != 0x91000000:
        continue
    if ((w >> 10) & 0xFFF) != 0x6A0:
        continue
    rd = w & 0x1F
    rn = (w >> 5) & 0x1F
    # window: is rd x0 and followed by ret (or mov x0,rd ; ret)
    for k in range(4, 32, 4):
        if i + k >= n:
            break
        w2 = struct.unpack_from("<I", text, i + k)[0]
        if w2 == 0xD65F03C0:                     # ret
            print("0x%08x  add x%d,x%d,#0x6a0 ; ret at +0x%x"
                  % (tv + i + GHI, rd, rn, k))
            break
        if w2 & 0xFFE0FFE0 == 0xAA0003E0:        # mov xN, xM
            pass
