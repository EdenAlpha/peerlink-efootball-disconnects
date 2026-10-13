#!/usr/bin/env python3
"""read_cfgdefaults.py -- dump default timeout ints set by cfg ctor FUN_07f1e420."""
import struct
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
e = Elf(SO)
# vaddr = ghidra - 0x100000
for base, start in ((0x73daf0, 0x58), (0x742270, 0x68),
                    (0x7476f0, 0x78), (0x7494d0, 0x88)):
    raw = e.va_read(base, 16)
    vals = struct.unpack("<4I", raw)
    print("vaddr %#x -> cfg+%#x: %s" % (base, start,
          ", ".join("+%#x=%d" % (start + 4 * i, v) for i, v in enumerate(vals))))
