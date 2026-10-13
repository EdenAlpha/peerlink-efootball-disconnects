#!/usr/bin/env python3
"""rp_tables.py -- decode the STUN/RP attribute dispatch tables of the
parser (Ghidra fn 0x7df86f0) in the previous-update libUE4.so.

Three switches (same shape as the name mapper 0x7debc10):
  P1 codes 0x0000-0x002a  u16 table @0xd8fb90 base 0x7df89d0
  P3 codes 0x8020-0x802c  u16 table @0xd8fbe6 base 0x7df8b14
  P2 codes 0x9090-0x909d  u8  table @0xd8fc00 base 0x7df8a84
"""
import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native\lib\arm64-v8a\libUE4.so")
buf = open(SO, "rb").read()
IB = 0x100000


def code_file(g):
    return g - IB - 0x4000


def data_file(g):
    return g - IB


def name_at(foff):
    if foff is None or foff < 0 or foff >= len(buf):
        return "?"
    s = buf[foff:foff + 48]
    out = b""
    for c in s:
        if 32 <= c < 127:
            out += bytes([c])
        else:
            break
    return out.decode() if len(out) >= 3 else "?"


def adrp_target(blk_file, w1, w2):
    """decode adrp+add -> rodata file offset (string), else None"""
    if (w1 & 0x9F000000) != 0x90000000:
        return None
    if (w2 & 0xFF800000) == 0x91000000:
        immlo = (w1 >> 29) & 3
        immhi = (w1 >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        elf_pc = blk_file + 0x4000
        page = (elf_pc & ~0xFFF) + imm * 4096
        imm12 = (w2 >> 10) & 0xFFF
        if (w2 >> 22) & 1:
            imm12 <<= 12
        return page + imm12
    return None


for label, lo, base_g, tab_g, n, wide in [
        ("P1", 0x0000, 0x7df89d0, 0xd8fb90, 43, True),
        ("P3", 0x8020, 0x7df8b14, 0xd8fbe6, 13, True),
        ("P2", 0x9090, 0x7df8a84, 0xd8fc00, 14, False)]:
    base = code_file(base_g)
    tab = data_file(tab_g)
    print("== %s codes 0x%x..0x%x (table@0x%x %s)"
          % (label, lo, lo + n - 1, tab, "u16" if wide else "u8"))
    for i in range(n):
        if wide:
            off = struct.unpack_from("<H", buf, tab + 2 * i)[0] * 4
        else:
            off = buf[tab + i] * 4
        blk = base + off
        found = []
        # scan the case block for adrp+add string loads and mov-immediates
        for j in range(0, 24):
            w1, w2 = struct.unpack_from("<II", buf, blk + 4 * j)
            tgt = adrp_target(blk + 4 * j, w1, w2)
            if tgt is not None:
                nm = name_at(tgt)
                if nm != "?":
                    found.append(nm)
            if (w2 & 0xFF800000) == 0x52800000:  # movz w
                imm = ((w2 >> 5) & 0xFFFF) << ((w2 >> 21) & 3)
                rd = w2 & 31
                if imm >= 0x8000:
                    found.append("mov w%d,#0x%x" % (rd, imm))
            if (w2 & 0xFC000000) == 0x14000000:  # b
                break
            if (w2 & 0xFFFFFC1F) == 0xD65F0000:  # ret
                break
        print("  0x%04x -> %s   [%s]" % (lo + i, ("0x%x" % blk),
                                         ", ".join(found[:4])))
