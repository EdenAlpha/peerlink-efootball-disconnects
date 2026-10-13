#!/usr/bin/env python3
"""dec_jt.py -- decode FUN_07eeb608 state jump table (halfwords @ 0xca5102)."""
import struct
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
e = Elf(SO)

def va_read(va, n):
    return e.va_read(va, n)

base = 0x7deb8bc          # adr x13 target (vaddr)
tab = 0xca5102            # vaddr of halfword table
cases = {
    0x7debeb4: "TIMEOUT?",  # not used here; we map targets instead
}
# targets observed:
names = {
    0x7debea8: "INIT",
    0x7debef8: "TIMEOUT",
    0x7deb004: "?",
}
# rather: list each entry target
for s in range(16):
    hw = struct.unpack_from("<H", va_read(tab + 2 * s, 2))[0]
    tgt = base + hw * 4
    print("state %-2d -> 0x%08x" % (s, tgt))
