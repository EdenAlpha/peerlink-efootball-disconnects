#!/usr/bin/env python3
"""relay_xref.py -- locate the relay connect/framing code in libUE4.so.

Anchors: the literals the relay client and its session parser touch
('relayedAddress', 'relayParam', 'gamerelay', 'is_local_gamerelay',
'build_gamerelay_num').  For each, find adrp->page->add materialisation
sites, then dump the instruction neighborhood: the connect flow shows
socket/connect (mov x2,#6 = SOCK_STREAM), the2-byte hello, and the
token handling.

  python relay_xref.py
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

KEYS = ("relayedAddress", "relayParam", "gamerelay",
        "is_local_gamerelay", "build_gamerelay_num")

data = open(SO, "rb").read()


def find_literal(s):
    # packed rodata name table: strings are NOT NUL-terminated and not
    # aligned -- find raw byte runs; the adrp+add scan filters hits
    b = s.encode()
    offs, start = [], 0
    while True:
        i = data.find(b, start)
        if i < 0:
            return offs
        offs.append(i)
        start = i + 1


def decode(off, w):
    pc = off
    if w & 0xFC000000 == 0x94000000:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        return "bl       #0x%x" % (pc + imm * 4)
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
        return "add      x%d, x%d, #0x%x" % (w & 31, (w >> 5) & 31, imm)
    if w == 0xD503201F:
        return "nop"
    if (w & 0xFFE0001F) == 0xAA0003E0 and (w >> 5) & 31 == 31:
        return "mov      x%d, xzr" % (w & 31)
    if w & 0xFF800000 == 0x52800000:               # movz w
        imm = (w >> 5) & 0xFFFF
        return "mov      w%d, #0x%x" % (w & 31, imm)
    if w & 0xFF800000 == 0x12800000:               # movn w
        imm = (w >> 5) & 0xFFFF
        return "mov      w%d, #~0x%x" % (w & 31, imm)
    if (w & 0xFFE00C00) == 0xB4000000:             # cbz
        imm = ((w >> 5) & 0x7FFFF)
        if imm & 0x40000:
            imm -= 0x80000
        return "cbz      x%d, #0x%x" % (w & 31, pc + imm * 4)
    if (w & 0xFFE00C00) == 0xB4000000 | 0x01000000:
        imm = ((w >> 5) & 0x7FFFF)
        if imm & 0x40000:
            imm -= 0x80000
        return "cbnz     x%d, #0x%x" % (w & 31, pc + imm * 4)
    return None


want_pages = {}
for k in KEYS:
    for off in find_literal(k):
        want_pages.setdefault(off & ~0xFFF, []).append((k, off))

print("literal pages:")
for k in KEYS:
    print("  %-22s %s" % (k, ["0x%x" % o for o in
                              [x for pg in want_pages.values()
                               for (kk, x) in pg if kk == k]][:5]))

sites = []
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
    if page not in want_pages:
        continue
    for b in range(1, 17):
        off2 = pc + b * 4
        if off2 + 4 > len(data):
            break
        w2 = struct.unpack_from("<I", data, off2)[0]
        if (w2 & 0xFF800000) in (0x91000000, 0x11000000):
            imm12 = (w2 >> 10) & 0xFFF
            for (k, lo) in want_pages[page]:
                if imm12 == (lo & 0xFFF):
                    sites.append((off2, k))

sites.sort()
print("\nsites: %s" % [(hex(a), k) for a, k in sites])

# dump neighborhood of each site (window varies by key importance)
for site_off, key in sites:
    if key in ("relayedAddress", "relayParam", "build_gamerelay_num"):
        lo = max(0, site_off - 0x80)
        hi = min(len(data) - 4, site_off + 0xC0)
        print("\n== %s @ 0x%x ==" % (key, site_off))
        for a in range(lo & ~3, hi, 4):
            w = struct.unpack_from("<I", data, a)[0]
            d = decode(a, w)
            if d:
                mark = ">>" if a == site_off else "  "
                print("%s 0x%08x  %s" % (mark, a, d))
