#!/usr/bin/env python3
"""scan_strptr.py -- find stored 64-bit pointers to given Ghidra string addresses."""
import struct, sys
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
      r"\efootball-apk\native1110\libUE4.so")

def main():
    addrs = [int(a, 16) for a in sys.argv[1:]]
    e = Elf(SO)
    d = e.data
    secs = e.sections  # list of tuples incl (name, type, addr, off, size)?
    def off2va(i):
        for s in secs:
            # s = (name, type, addr, off, size)
            try:
                nm, ty, addr, off, size = s
            except Exception:
                continue
        return i
    for a in addrs:
        out = []
        for va in (a - 0x100000, a):
            b = struct.pack("<Q", va)
            i = d.find(b)
            while i != -1:
                out.append(hex(i))
                i = d.find(b, i + 1)
                if len(out) > 40:
                    break
        print(hex(a), out if out else "NONE")

main()
