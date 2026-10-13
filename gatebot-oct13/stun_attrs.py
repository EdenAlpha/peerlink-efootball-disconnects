#!/usr/bin/env python3
"""stun_attrs.py -- decode Konami's STUN/RP attribute codes from the
attribute-name switch in the previous-update libUE4.so (Ghidra fn 0x7debc10).

ELF layout: LOAD2 .text vaddr = file offset + 0x4000; rodata (LOAD1)
vaddr == file offset. Ghidra adds imageBase 0x100000 to everything.
"""
import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native\lib\arm64-v8a\libUE4.so")
buf = open(SO, "rb").read()
IB = 0x100000


def code_file(gaddr):
    return gaddr - IB - 0x4000


def data_file(gaddr):
    return gaddr - IB


def name_at(foff):
    s = buf[foff:foff + 48]
    out = b""
    for c in s:
        if 32 <= c < 127:
            out += bytes([c])
        else:
            break
    return out.decode()


for label, lo, base_g, tab_g, n in [
        ("A", 0x0000, 0x7debc48, 0xd8fb25, 43),
        ("C", 0x8020, 0x7debcb0, 0xd8fb50, 13),
        ("B", 0x9090, 0x7debc7c, 0xd8fb5d, 14)]:
    base = code_file(base_g)
    tab = data_file(tab_g)
    print("== switch %s: codes 0x%x..0x%x  (table @0x%x)"
          % (label, lo, lo + n - 1, tab))
    for i in range(n):
        blk = base + buf[tab + i] * 4
        elf_pc = blk + 0x4000
        w1, w2 = struct.unpack_from("<II", buf, blk)
        if (w1 & 0x9F000000) == 0x90000000 and (w2 & 0xFF800000) == 0x91000000:
            immlo = (w1 >> 29) & 3
            immhi = (w1 >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            page = (elf_pc & ~0xFFF) + imm * 4096
            imm12 = (w2 >> 10) & 0xFFF
            if (w2 >> 22) & 1:
                imm12 <<= 12
            print("  0x%04x -> %-28s" % (lo + i, name_at(page + imm12)))
        else:
            print("  0x%04x -> (block %08x w1=%08x w2=%08x)"
                  % (lo + i, blk, w1, w2))
