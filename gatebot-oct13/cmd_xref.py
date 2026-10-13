#!/usr/bin/env python3
"""cmd_xref.py -- xref gate command literals to land in relay client code.

Usage: python cmd_xref.py CmdGetGamerelayQualityCheckList
                     CmdSetLocalGamerelayList CmdSetGamerelayQuality
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

sys.argv = [sys.argv[0]] + sys.argv[1:]
KEYS = sys.argv[1:] or [
    "CmdGetGamerelayQualityCheckList",
    "CmdSetLocalGamerelayList",
    "CmdSetGamerelayQuality",
]

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

    sections = {nm(s[0]): s for s in shs}
    dynsym, dynstr, rela = sections[".dynsym"], sections[".dynstr"], \
        sections[".rela.plt"]
    plt = sections.get(".plt") or sections.get(".plt.got")
    dstr = buf[dynstr[4]:dynstr[4] + dynstr[5]]
    entsz = dynsym[9] or 24

    def dyn_name(i):
        (st_name,) = struct.unpack_from("<I", buf, dynsym[4] + i * entsz)
        end = dstr.find(b"\x00", st_name)
        return dstr[st_name:end].decode(errors="replace")

    rela_off, rela_sz, rela_ent = rela[4], rela[5], rela[9] or 24
    syms = {}
    for i in range(rela_sz // rela_ent):
        r_info = struct.unpack_from("<Q", buf, rela_off + i * rela_ent + 8)[0]
        syms[plt[3] + 16 * (i + 1)] = dyn_name(r_info >> 32)
    return syms


plt_syms = parse_elf(data)


def dis(pc, w):
    if w == 0xD65F03C0:
        return "ret"
    if w == 0xD503237F:
        return "pacibsp"
    if w == 0xD503201F:
        return "nop"
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return "blr      x%d" % ((w >> 5) & 31)
    if w & 0xFC000000 == 0x94000000:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        tgt = pc + imm * 4
        name = plt_syms.get(tgt)
        return "bl       %s%s" % (name or "#0x%x" % tgt,
                                  "  ; PLT" if name else "")
    if w & 0xFC000000 == 0x14000000:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        return "b        #0x%x" % (pc + imm * 4)
    if w & 0x9F000000 == 0x90000000:
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        return "adrp     x%d, #0x%x" % (w & 31, (pc & ~0xFFF) + imm * 4096)
    if w & 0xFF800000 == 0x91000000:
        imm = (w >> 10) & 0xFFF
        if (w >> 22) & 1:
            imm <<= 12
        return "add      x%d, x%d, #0x%x%s" % (
            w & 31, (w >> 5) & 31, imm, ", lsl #12" if (w >> 22) & 1 else "")
    if w & 0xFF800000 == 0x52800000:
        return "mov      w%d, #0x%x" % (w & 31, (w >> 5) & 0xFFFF)
    if (w & 0xFFE00C00) == 0xB4000000:
        imm = (w >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return "cbz      x%d, #0x%x" % (w & 31, pc + imm * 4)
    if (w & 0xFFE00C00) == 0xB5000000:
        imm = (w >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return "cbnz     x%d, #0x%x" % (w & 31, pc + imm * 4)
    if (w & 0xFF000010) == 0x54000000:
        imm = (w >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        conds = "eq ne cs cc mi pl vs vc hi ls ge lt gt le".split()
        return "b.%-3s    #0x%x" % (conds[w & 0xF], pc + imm * 4)
    if w & 0xFF000000 == 0x71000000:
        imm = (w >> 10) & 0xFFF
        rn, rd = (w >> 5) & 31, w & 31
        x = "x" if w & 0x80000000 else "w"
        if rd == 31:
            return "cmp      %s%d, #0x%x" % (x, rn, imm)
        return "subs     %s%d, %s%d, #0x%x" % (x, rd, x, rn, imm)
    if (w & 0x3B000000) == 0x39000000:
        size = 1 << ((w >> 30) & 3)
        v = (w >> 26) & 1
        op = (w >> 22) & 3
        if op in (2, 3):
            rt, rn = w & 31, (w >> 5) & 31
            imm = ((w >> 10) & 0xFFF) * size
            load = "ldr" if op == 3 else "str"
            ext = {1: "b", 2: "h", 4: "w", 8: "x"}[size] if not v else "x"
            return "%s      %s%d, [x%d, #0x%x]" % (load, ext, rt, rn, imm)
    if (w & 0xFFC003E0) == 0xA98003E0:
        imm7 = (w >> 15) & 0x7F
        if imm7 & 0x40:
            imm7 -= 0x80
        return "stp      x%d,x%d, [sp, #%d]!" % (
            (w >> 10) & 31, w & 31, imm7 * 8)
    return None


def string_at(tgt):
    if not (0 <= tgt < len(data)):
        return None
    s = data[tgt:tgt + 80]
    pref = b""
    for c in s:
        if 32 <= c < 127:
            pref += bytes([c])
        else:
            break
    if len(pref) >= 3:
        return pref.decode()
    return None


# locate literals (raw + NUL variants)
found = {}
for k in KEYS:
    offs = []
    b = k.encode()
    st = 0
    while True:
        i = data.find(b, st)
        if i < 0:
            break
        offs.append(i)
        st = i + 1
    found[k] = offs
    print("%-40s %s" % (k, ["0x%x" % o for o in offs][:8]))

# xref scan
want = {}
for k, offs in found.items():
    for off in offs:
        want.setdefault(off & ~0xFFF, []).append((off, k))

hits = []
for wi in range(len(data) // 4):
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
    if page not in want:
        continue
    for b in range(1, 40):
        off2 = pc + b * 4
        if off2 + 4 > len(data):
            break
        w2 = struct.unpack_from("<I", data, off2)[0]
        if (w2 & 0xFF800000) == 0x91000000:
            imm12 = (w2 >> 10) & 0xFFF
            if (w2 >> 22) & 1:
                imm12 <<= 12
            for (lo, k) in want[page]:
                if imm12 == (lo & 0xFFF):
                    hits.append((off2, k, lo))
hits.sort()
print("\nxrefs: %d" % len(hits))
for h in hits:
    print("  0x%x  %s" % (h[0], h[1]))


def fn_back(site, limit=0x4000):
    for i in range(0, limit, 4):
        off = (site & ~3) - i
        if off < 0:
            break
        w = struct.unpack_from("<I", data, off)[0]
        if (w & 0xFFC003E0) == 0xA98003E0 or (w & 0xFFC003FF) == 0xD10003FF:
            return off
    return None


def dump(lo, hi, mark=None):
    adrp_reg = {}
    for a in range(lo & ~3, hi, 4):
        w = struct.unpack_from("<I", data, a)[0]
        d = dis(a, w)
        if w & 0x9F000000 == 0x90000000:
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            adrp_reg[w & 31] = (a & ~0xFFF) + imm * 4096
        if d is None and (w & 0xFF800000) == 0x91000000:
            rd, rn = w & 31, (w >> 5) & 31
            if rn in adrp_reg:
                imm = (w >> 10) & 0xFFF
                if (w >> 22) & 1:
                    imm <<= 12
                tgt = adrp_reg[rn] + imm
                s = string_at(tgt)
                if s:
                    d = "add      x%d -> '0x%x %s'" % (rd, tgt, s)
        if d is None:
            continue
        m = ">>" if a == mark else "  "
        print("%s 0x%08x  %s" % (m, a, d))


for site, key, lo in hits[:4]:
    fn = fn_back(site)
    print("\n=== %s @ 0x%x (fn ~%s) ===" % (key, site,
                                            hex(fn) if fn else "?"))
    if fn:
        dump(fn, min(len(data) - 4, fn + 0x1c0))
    print("--- site context ---")
    dump(max(0, site - 0x40), min(len(data) - 4, site + 0x140), mark=site)
