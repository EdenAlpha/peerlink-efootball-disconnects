#!/usr/bin/env python3
"""port_xref.py -- find hardcoded relay ports 5735/5736 immediates.

movz w?, #0x1663 / #0x6316 (htons) etc. If found, land in that
function: it's the relay connect candidate builder.
"""
import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()

targets = {
    0x1663: "5735 raw",
    0x6316: "5735 htons-swapped",
    0x1664: "5736 raw",
    0x6416: "5736 htons-swapped",
    0x1BB: "443 raw",
    0xBB01: "443 htons-swapped",
}

hits = []
for wi in range(len(data) // 4):
    w = struct.unpack_from("<I", data, wi * 4)[0]
    # movz wd, #imm16
    if w & 0xFF800000 == 0x52800000:
        imm = (w >> 5) & 0xFFFF
        if imm in targets:
            hits.append((wi * 4, "movz", imm, w & 31))
    # movk wd, #imm16, lsl #16 (upper half of a 32-bit const)
    if w & 0xFF800000 == 0x52A00000:
        imm = (w >> 5) & 0xFFFF
        if imm in (0x1663, 0x1664, 0x6316, 0x6416):
            hits.append((wi * 4, "movk16", imm, w & 31))

print("hits: %d" % len(hits))
for off, kind, imm, rd in hits[:60]:
    print("  0x%x  %s w%d, #0x%x (%s)" % (off, kind, rd, imm, targets.get(imm, "")))
