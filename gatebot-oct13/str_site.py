#!/usr/bin/env python3
"""str_site.py -- find code sites in 11.1.0 that reference an exact literal.

  python str_site.py reflexive_address nat_type game_sycom ntl_address_list

For each literal: find adrp (page) + add (exact imm12) pairs, walk back to
the enclosing function prologue, print site + function entry. Use
dump_fn.py <entry> to read the function.
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

# pre-scan: adrp pages present (avoid recompute per literal is impossible;
# we need per-instruction decode anyway. Keep single pass per literal.)

PROLOGUE = (
    lambda w: (w & 0xFFC07FFF) == 0xA9807BFD or   # stp x29,x30,[sp,#imm]!
              (w & 0xFFC003FF) == 0xD10003FF or    # sub sp,sp,#imm
              (w & 0xFFE07FFF) == 0xA9A07BFD or    # stp x29,x30,[sp,#imm]!
              (w & 0xFFFFFC1F) == 0xD503237F       # pacibsp
)


def fn_back(site, limit=0x10000):
    seen_pac = False
    for i in range(0, limit, 4):
        off = (site & ~3) - i
        if off < text_lo:
            return None
        w = struct.unpack_from("<I", data, off)[0]
        if (w & 0xFFFFFC1F) == 0xD503237F:  # pacibsp
            return off - 4 if seen_pac else off
        if (w & 0xFFC003FF) == 0xD10003FF:  # sub sp,sp,#imm
            return off
        if (w & 0xFFC07FFF) == 0xA9807BFD:  # stp x29,x30,[sp,#imm]!
            return off
        if (w & 0xFF800000) == 0xA9000000 and (w & 0x000007FF) == 0x000003E0:
            # stp x29, x30, [x?, #imm] (not pre-index) -- only trust
            # immediately after sub sp (handled above); skip
            pass
    return None


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
    hits = []
    for o in offs:
        page = o & ~0xFFF
        want12 = o & 0xFFF
        # single pass over .text
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
            pg = (pc & ~0xFFF) + imm * 4096
            if pg != page:
                continue
            rd = w & 31
            for j in range(1, 10):
                w2 = struct.unpack_from("<I", data, pc + j * 4)[0]
                if (w2 & 0xFF800000) == 0x91000000:  # add imm
                    imm12 = (w2 >> 10) & 0xFFF
                    if (w2 >> 22) & 1:
                        continue  # shifted -- not our small offset
                    rn = (w2 >> 5) & 31
                    if imm12 == want12 and rn == rd:
                        hits.append((pc, pc + j * 4, o))
                        break
                if (w2 & 0xFF000000) in (0x91000000, 0x91400000):
                    continue
                if w2 & 0x9F000000 == 0x90000000:
                    break  # another adrp -> moved on
    for adrp_pc, add_pc, o in hits[:20]:
        f = fn_back(add_pc)
        print("  site adrp=0x%x add=0x%x  fn=%s  str=0x%x"
              % (adrp_pc, add_pc, ("0x%x" % f) if f else "?", o))
    if not hits:
        print("  NO adrp+add ref (table-driven?)")
