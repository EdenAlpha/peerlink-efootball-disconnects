#!/usr/bin/env python3
"""find_callers_full.py -- like find_callers.py but scans ALL of .text.

  python find_callers_full.py 07e0afcc 07f1f33c ...
Prints Ghidra addresses.
"""
import struct
import sys
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000

def main():
    targets = {int(a, 16) for a in sys.argv[1:]}
    e = Elf(SO)
    _, _, _, tv, to, ts = e.sec(".text")
    text = e.read(to, ts)
    hits = []
    for i in range(0, len(text) - 3, 4):
        w = struct.unpack_from("<I", text, i)[0]
        op = w & 0xFC000000
        if op != 0x94000000 and op != 0x14000000:
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        pc = tv + i
        tgt = pc + (imm << 2)
        gh = tgt + GHI
        if gh in targets:
            hits.append((pc + GHI, gh, "bl" if op == 0x94000000 else "b"))
    print("hits: %d" % len(hits))
    for a, t, k in sorted(hits):
        print("  %#010x  %s -> %#010x" % (a, k, t))
    for t in sorted(targets):
        print("  target %#010x : %d" % (t, sum(1 for h in hits if h[1] == t)))

main()
