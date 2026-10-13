#!/usr/bin/env python3
"""addr_xref.py -- locate code referencing 'address_ipv4' and show context.

Decodes just enough ARM64 (adrp / add-imm / bl) to find every site that
materialises the address_ipv4 literal, then dumps the instruction
neighborhood so we can see whether the attached value is a map (setkey
pattern: bl 0x2fcc828) or a list (loop + push), and which key strings
the same region loads (sibling keys of the address map).
"""
import re
import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()

TARGET = 0xC2A15F          # address_ipv4 literal
PAGE = TARGET & ~0xFFF     # 0xc2a000

SETKEY = 0x2FCC828


def words_at(off, n):
    return struct.unpack("<%dI" % n, data[off:off + 4 * n])


def decode(off, w):
    pc = off
    if w & 0xFC000000 == 0x94000000:            # bl
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        return "bl       #0x%x" % (pc + imm * 4)
    if w & 0x9F000000 == 0x90000000:            # adrp
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        return "adrp     x%d, #0x%x" % (w & 31, (pc & ~0xFFF) + imm * 4096)
    if w & 0xFF800000 == 0x91000000:            # add imm (64)
        imm = (w >> 10) & 0xFFF
        sh = (w >> 22) & 1
        if sh:
            imm <<= 12
        return "add      x%d, x%d, #0x%x" % (w & 31, (w >> 5) & 31, imm)
    return None


# find all add-imm instructions with imm12 == (TARGET & 0xFFF) == 0x15f
hits = []
for m in re.finditer(rb"\x1f\x7c\x05\x91", data):   # LE of 0x91057C1F (Rd=x31 variant search space) -- too narrow
    pass
# general scan instead
for off in range(0, len(data) - 4, 4):
    w = struct.unpack_from("<I", data, off)[0]
    if (w & 0xFF800000) == 0x91000000 and ((w >> 10) & 0xFFF) == 0x15F:
        hits.append(off)

print("add #0x15f sites: %d" % len(hits))
for off in hits:
    # check an adrp to 0xc2a000 within the previous 16 words
    ok = False
    for back in range(4, 68, 4):
        wb = struct.unpack_from("<I", data, off - back)[0]
        d = decode(off - back, wb)
        if d and d.startswith("adrp") and "#0x%x" % PAGE in d:
            ok = True
            break
    if not ok:
        continue
    print("\n== site 0x%x ==" % off)
    lo = max(0, off - 0x60)
    for a in range(lo, off + 0x50, 4):
        w = struct.unpack_from("<I", data, a)[0]
        d = decode(a, w)
        if d:
            mark = ">>" if a == off else "  "
            print("%s 0x%08x  %s" % (mark, a, d))
