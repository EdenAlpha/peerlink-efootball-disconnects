#!/usr/bin/env python3
"""relay_connect.py -- land inside the relay/TURN connect code in libUE4.so.

Anchors: the NUL-terminated source-path literals (NtlHelper.cpp,
SessionStrategyP2pFullMesh*.cpp, MatchOnline*.cpp).  Xrefs via adrp+add;
walk back to the function prologue; dump the neighborhood with PLT calls
annotated (socket/connect/send/recv from .rela.plt).

  python relay_connect.py [max_sites]
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

KEYS = (
    r"\Ntl\ntl\NtlHelper.cpp",
    "SessionStrategyP2pFullMeshWithTurn.cpp",
    "SessionStrategyP2pFullMeshTurnOnly.cpp",
    "MatchOnlineObserverForPesServer.cpp",
    "MatchOnlineNegotiator.cpp",
    "MatchOnlineSession.cpp",
    "MatchOnlineDataSync.cpp",
)

data = open(SO, "rb").read()


# ---------- ELF: PLT symbol map ----------
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
    dynsym = sections.get(".dynsym")
    dynstr = sections.get(".dynstr")
    rela = sections.get(".rela.plt")
    plt = sections.get(".plt") or sections.get(".plt.got")
    if not (dynsym and dynstr and rela and plt):
        return None, {}
    dstr = buf[dynstr[4]:dynstr[4] + dynstr[5]]
    entsz = dynsym[9] or 24

    def dyn_name(i):
        (st_name,) = struct.unpack_from("<I", buf, dynsym[4] + i * entsz)
        end = dstr.find(b"\x00", st_name)
        return dstr[st_name:end].decode(errors="replace")

    rela_off, rela_sz, rela_ent = rela[4], rela[5], rela[9] or 24
    plt_addr = plt[3]
    n = rela_sz // rela_ent
    syms = {}
    for i in range(n):
        r_info = struct.unpack_from("<Q", buf, rela_off + i * rela_ent + 8)[0]
        sym_idx = r_info >> 32
        name = dyn_name(sym_idx)
        # PLT0 (16 bytes) + i-th entry
        syms[plt_addr + 16 * (i + 1)] = name
    return plt_addr, syms


plt_addr, plt_syms = parse_elf(data)
print("PLT: %d imports @ 0x%x" % (len(plt_syms), plt_addr or 0))
interesting = [n for n in plt_syms.values()
               if n in ("socket", "connect", "send", "recv", "sendto",
                        "recvfrom", "setsockopt", "getaddrinfo", "htons",
                        "htonl", "close", "shutdown")]
print("socket-family imports: %s" % sorted(set(interesting)))


# ---------- disassembler ----------
def dis(pc, w):
    if w == 0xD503201F:
        return "nop"
    if w == 0xD65F03C0:
        return "ret"
    if w == 0xD503237F:
        return "pacibsp"
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return "blr      x%d" % ((w >> 5) & 31)
    if w & 0xFC000000 == 0x94000000:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        tgt = pc + imm * 4
        name = plt_syms.get(tgt)
        if name:
            return "bl       %s  ; plt 0x%x" % (name, tgt)
        return "bl       #0x%x" % tgt
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
        sh = (w >> 22) & 3
        return "add      x%d, x%d, #0x%x%s" % (
            w & 31, (w >> 5) & 31, imm, ", lsl #12" if sh == 1 else "")
    if w & 0xFF800000 == 0x52800000:
        return "mov      w%d, #0x%x" % (w & 31, (w >> 5) & 0xFFFF)
    if w & 0xFF800000 == 0x52A00000:
        return "movk     w%d, #0x%x, lsl #16" % (w & 31, (w >> 5) & 0xFFFF)
    if w & 0xFF800000 == 0x12800000:
        return "mov      w%d, #~0x%x" % (w & 31, (w >> 5) & 0xFFFF)
    if w & 0xFF800000 == 0xD2800000:
        return "mov      x%d, #0x%x" % (w & 31, (w >> 5) & 0xFFFF)
    if w & 0xFF800000 == 0xF2800000:
        return "movk     x%d, #0x%x, lsl #16" % (w & 31, (w >> 5) & 0xFFFF)
    if w & 0xFF800000 == 0xD2A00000:
        return "movk     x%d, #0x%x, lsl #32" % (w & 31, (w >> 5) & 0xFFFF)
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
        return "subs     w%d(cmp), #0x%x" % ((w >> 5) & 31 if (w >> 5) & 31 != 31 else 0,
                                             (w >> 10) & 0xFFF)
    if w & 0xFFE00C00 == 0xB4000000:
        imm = (w >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return "cbz      x%d, #0x%x" % (w & 31, pc + imm * 4)
    # ldr/str unsigned imm (64/32)
    if (w & 0x3B000000) == 0x39000000 or (w & 0x3B000000) == 0x38000000:
        size = 1 << ((w >> 30) & 3)
        v = (w >> 26) & 1
        op = (w >> 22) & 3
        if op in (2, 3):
            rt = w & 31
            rn = (w >> 5) & 31
            imm = ((w >> 10) & 0xFFF) * size
            load = "ldr" if op == 3 else "str"
            ext = "x" if v or size == 8 else ("w" if size == 4 else "b")
            if size == 2:
                ext = "h"
            return "%s      %s%d, [x%d, #0x%x]" % (load, ext, rt, rn, imm)
    return None


def find_literal_nul(s):
    b = s.encode() + b"\x00"
    offs, start = [], 0
    while True:
        i = data.find(b, start)
        if i < 0:
            return offs
        offs.append(i)
        start = i + 1


# collect sites
sites = []
for k in KEYS:
    for off in find_literal_nul(k):
        sites.append((off, k))
print("\nliterals: %s" % [("0x%x" % o, k[-34:]) for o, k in sites])

# adrp -> page, add with imm12 == off & 0xfff
want = {}
for off, k in sites:
    want.setdefault(off & ~0xFFF, []).append((off, k))

hits = []
n_words = len(data) // 4
for wi in range(n_words):
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
    for b in range(1, 20):
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
print("xref sites: %d" % len(hits))
for h in hits[:20]:
    print("  0x%x  %s -> literal 0x%x" % (h[0], h[1][-40:], h[2]))


def prologue_back(site, limit=0x4000):
    """walk back to the nearest stp x29,x30,[sp,#imm]!"""
    best = None
    a = site & ~3
    for i in range(0, limit, 4):
        off = a - i
        if off < 0:
            break
        w = struct.unpack_from("<I", data, off)[0]
        if (w & 0xFFC07FFF) == 0xA9807BFD:
            best = off
            if i > 0:
                break
    return best


max_sites = int(sys.argv[1]) if len(sys.argv) > 1 else 6
for site, key, lo in hits[:max_sites]:
    fn = prologue_back(site)
    lo_b = fn if fn is not None else max(0, site - 0x100)
    hi_b = min(len(data) - 4, site + 0x280)
    print("\n=== %s xref @ 0x%x (fn~0x%s) ===" % (
        key.split("\\")[-1], site, format(fn, "x") if fn is not None else "?"))
    # track last adrp for string annotation
    adrp_reg = {}
    for a in range(lo_b & ~3, hi_b, 4):
        w = struct.unpack_from("<I", data, a)[0]
        d = dis(a, w)
        if w & 0x9F000000 == 0x90000000:
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            adrp_reg[w & 31] = (a & ~0xFFF) + imm * 4096
            d = d or "adrp"
        if d is None:
            if w & 0xFF800000 == 0x91000000:
                rd, rn = w & 31, (w >> 5) & 31
                if rn in adrp_reg:
                    imm = (w >> 10) & 0xFFF
                    if (w >> 22) & 1:
                        imm <<= 12
                    tgt = adrp_reg[rn] + imm
                    if 0 <= tgt < len(data):
                        s = data[tgt:tgt + 44]
                        end = s.find(b"\x00")
                        if 0 <= end <= 40:
                            pr = s[:end]
                            if all(32 <= c < 127 for c in pr):
                                d = "add      x%d, x%d -> '%s'" % (
                                    rd, rn, pr.decode())
                    if d is None:
                        continue
                else:
                    continue
            else:
                continue
        mark = ">>" if a == site else "  "
        print("%s 0x%08x  %s" % (mark, a, d))
