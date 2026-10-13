#!/usr/bin/env python3
"""aps2_xref.py -- xref rodata literals in the 11.1.0 libUE4.so through the
packed Android RELA section (SHT_ANDROID_RELA / APS2), then map table slots
back to code (adrp+add building the slot address) and to functions.

  python aps2_xref.py reflexive_address nat_type game_sycom ntl_address_list

Prints literal -> string vaddr -> table slot(s) -> code site -> function entry.
Then: python dump_fn.py <entry> to read the function.
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

KEYS = sys.argv[1:] or ["reflexive_address", "nat_type"]
data = open(SO, "rb").read()

# ---------------------------------------------------------------- elf
(e_shoff,) = struct.unpack_from("<Q", data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
shs = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
       for i in range(e_shnum)]
shstr = shs[e_shstrndx]
_strtab = data[shstr[4]:shstr[4] + shstr[5]]


def _nm(off):
    end = _strtab.find(b"\x00", off)
    return _strtab[off:end].decode(errors="replace")


secs = {_nm(s[0]): s for s in shs}
text = secs[".text"]
text_lo, text_hi = text[3], text[3] + text[5]

# ------------------------------------------------------------- aps2
rela = secs[".rela.dyn"]
rela_off, rela_sz = rela[4], rela[5]
assert data[rela_off:rela_off + 4] == b"APS2", "not APS2 at 0x%x" % rela_off


class Uleb:
    def __init__(self, buf, pos):
        self.buf = buf
        self.pos = pos

    def u(self):
        r, s = 0, 0
        while True:
            b = self.buf[self.pos]
            self.pos += 1
            r |= (b & 0x7F) << s
            if not (b & 0x80):
                return r
            s += 7

    def s(self):
        r, s = 0, 0
        while True:
            b = self.buf[self.pos]
            self.pos += 1
            r |= (b & 0x7F) << s
            s += 7
            if not (b & 0x80):
                if b & 0x40:
                    r |= -(1 << s)
                return r


dec = Uleb(data, rela_off + 4)
end = rela_off + rela_sz
slots_by_addend = {}   # addend vaddr -> [slot vaddr]
nrel = 0
nother = 0
r_offset = 0
r_addend = 0
while dec.pos < end:
    group_size = dec.u()
    group_delta = dec.u()
    r_offset += group_delta
    for j in range(group_size):
        if j != 0:
            r_offset += dec.u()
        r_info = dec.u()
        rtype = r_info & 0xFFFFFFFF
        if rtype == 1027:  # R_AARCH64_RELATIVE
            r_addend += dec.s()
            slots_by_addend.setdefault(r_addend, []).append(r_offset)
            nrel += 1
        else:
            nother += 1
print("APS2: %d RELATIVE, %d other, endpos=0x%x (section end 0x%x)"
      % (nrel, nother, dec.pos, end))

# ------------------------------------------------- code refs (adrp scan)
print("scanning .text adrp ...")
adrps = []  # (pc, page, rd)
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
    adrps.append((pc, page, w & 31))
print("adrp count: %d" % len(adrps))
import bisect  # noqa: E402

adrps_by_pc = adrps
pages = sorted(set(p for _, p, _ in adrps))
page_start = {}
for i, (pc, page, rd) in enumerate(adrps):
    page_start.setdefault(page, i)


def adrp_window(page):
    i = page_start.get(page)
    if i is None:
        return ()
    out = []
    j = i
    while j < len(adrps) and adrps[j][1] == page:
        out.append(adrps[j])
        j += 1
    return out


def fn_back(site, limit=0x10000):
    for i in range(0, limit, 4):
        off = (site & ~3) - i
        if off < text_lo:
            return None
        w = struct.unpack_from("<I", data, off)[0]
        if (w & 0xFFFFFC1F) == 0xD503237F:  # pacibsp
            return off
        if (w & 0xFFC003FF) == 0xD10003FF:  # sub sp,sp,#imm
            return off
        if (w & 0xFFC07FFF) == 0xA9807BFD:  # stp x29,x30,[sp,#imm]!
            return off
    return None


def find_literal(k):
    b = k.encode()
    offs, st = [], 0
    while True:
        i = data.find(b, st)
        if i < 0:
            return offs
        offs.append(i)
        st = i + 1


for k in KEYS:
    offs = find_literal(k)
    print("== %s literal@%s" % (k, ["0x%x" % o for o in offs][:6]))
    for o in offs:
        for slot in slots_by_addend.get(o, [])[:10]:
            print("   slot 0x%x" % slot)
            spage = slot & ~0xFFF
            s12 = slot & 0xFFF
            for pc, page, rd in adrp_window(spage)[:200]:
                for j in range(1, 8):
                    w2 = struct.unpack_from("<I", data, pc + j * 4)[0]
                    if (w2 & 0xFF800000) == 0x91000000:
                        imm12 = (w2 >> 10) & 0xFFF
                        if not ((w2 >> 22) & 1) and imm12 == s12 \
                                and ((w2 >> 5) & 31) == rd:
                            f = fn_back(pc + j * 4)
                            print("      site adrp=0x%x fn=%s"
                                  % (pc, ("0x%x" % f) if f else "?"))
                            break
                else:
                    continue
                break
    if not any(slots_by_addend.get(o) for o in offs):
        print("   no relocation slot -> referenced by direct code only?")
