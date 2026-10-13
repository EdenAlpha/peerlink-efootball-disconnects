#!/usr/bin/env python3
"""probe_adrp.py -- how does 11.1.0 code reference a given rodata literal?

  python probe_adrp.py reflexive_address

Prints every adrp whose page contains the literal, plus the next 6 words
decoded loosely (add/mov/ldr immediates), so we can see the real reference
form (adrp+add, adrp+ldr-from-ptr-table, adr, ...).
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

KEYS = sys.argv[1:] or ["reflexive_address"]
data = open(SO, "rb").read()


def parse_elf(buf):
    (e_shoff,) = struct.unpack_from("<Q", buf, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3A)
    shs = [struct.unpack_from("<IIQQQQIIQQ", buf, e_shoff + i * e_shentsize)
           for i in range(e_shnum)]
    shstr = shs[e_shstrndx]
    strtab = buf[shstr[4]:shstr[4] + shstr[5]]

    def nm(off):
        end = strtab.find(b"\x00", off)
        return strtab[off:end].decode(errors="replace")

    return {nm(s[0]): s for s in shs}


secs = parse_elf(data)
text = secs[".text"]
text_lo, text_hi = text[3], text[3] + text[5]


def dec(pc, w):
    if (w & 0x9F000000) == 0x90000000:  # adrp
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (pc & ~0xFFF) + imm * 4096
        return "adrp x%d, 0x%x" % ((w >> 5) & 31, page)
    if (w & 0xFF800000) == 0x91000000:  # add imm
        imm12 = (w >> 10) & 0xFFF
        sh = (w >> 22) & 1
        if sh:
            imm12 <<= 12
        return "add x%d, x%d, #0x%x%s" % ((w >> 0) & 31, (w >> 5) & 31,
                                          imm12, ", lsl #12" if sh else "")
    if (w & 0xFF800000) == 0xF9400000:  # ldr imm
        imm12 = (w >> 10) & 0xFFF
        return "ldr x%d, [x%d, #0x%x]" % ((w >> 0) & 31, (w >> 5) & 31,
                                          imm12 * 8)
    if (w & 0xFF800000) == 0x91000000:
        return "add?"
    if (w & 0xFF000000) == 0x91000000:
        return "add x?, x?, #?"
    if w == 0xD503201F:
        return "nop"
    if (w & 0xFF000000) == 0x52800000:  # movz
        return "mov x%d, #0x%x" % ((w >> 0) & 31,
                                   ((w >> 5) & 0xFFFF) << ((w >> 21) & 3))
    if (w & 0xFC000000) == 0x94000000:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        return "bl 0x%x" % (pc + imm * 4)
    if w == 0xD65F03C0:
        return "ret"
    if (w & 0xFF000000) == 0x94000000:
        return "bl ?"
    if (w & 0xFFC00000) == 0xA9000000 or (w & 0xFFC00000) == 0xA9800000:
        return "stp"
    if (w & 0xFFC00000) == 0xF9000000:
        return "str"
    return "0x%08x" % w


for k in KEYS:
    b = k.encode()
    st, offs = 0, []
    while True:
        i = data.find(b, st)
        if i < 0:
            break
        offs.append(i)
        st = i + 1
    print("== %s literal@%s" % (k, ["0x%x" % o for o in offs][:6]))
    pages = set(o & ~0xFFF for o in offs)
    for o in offs:
        pages.add((o - 1) & ~0xFFF)  # string may straddle a page? no, but ok
    n = 0
    for wi in range(text_lo // 4, text_hi // 4):
        w = struct.unpack_from("<I", data, wi * 4)[0]
        if w & 0x9F000000 != 0x90000000:
            continue
        pc = wi * 4
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (pc & ~0xFFF) + imm * 4096
        if page not in pages:
            continue
        print("  adrp-site 0x%x -> page 0x%x" % (pc, page))
        for j in range(1, 7):
            w2 = struct.unpack_from("<I", data, pc + j * 4)[0]
            print("     +%-2d %s" % (j * 4, dec(pc + j * 4, w2)))
        n += 1
        if n >= 12:
            print("  ... (cap)")
            break
    if n == 0:
        print("  no adrp to that page found")
