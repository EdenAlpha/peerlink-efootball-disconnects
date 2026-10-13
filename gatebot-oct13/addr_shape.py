#!/usr/bin/env python3
"""addr_shape.py -- find the real shape of the address map in libUE4.so.

The ready body we hand-invented ({host_address, host_port,
reflexive_address, reflexive_port, nat_type}) is unverified -- a phone
that receives a malformed address map just says 'Unable to connect'.
This finds every code site that materialises each key literal (adrp ->
page -> add offset), then reports regions where MULTIPLE address keys
co-occur: that region is the map builder, and its instruction
neighborhood shows the real shape (map vs list) and value writers.

  python addr_shape.py
"""
import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

KEYS = ("host_address", "host_port", "reflexive_address",
        "reflexive_port", "nat_type", "address_ipv4", "address_ipv6",
        "ntl_address_list")

data = open(SO, "rb").read()
n_words = len(data) // 4


def find_literal(s):
    b = s.encode() + b"\x00"
    offs = []
    start = 0
    while True:
        i = data.find(b, start)
        if i < 0:
            return offs
        # 4-byte aligned literals only (rodata pools)
        if i % 4 == 0:
            offs.append(i)
        start = i + 1


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
        return ("adrp     x%d, #0x%x" % (w & 31,
                (pc & ~0xFFF) + imm * 4096))
    if w & 0xFF800000 == 0x91000000:            # add imm 64
        imm = (w >> 10) & 0xFFF
        if (w >> 22) & 1:
            imm <<= 12
        return "add      x%d, x%d, #0x%x" % (w & 31, (w >> 5) & 31, imm)
    if w & 0xFF800000 == 0x11000000:            # add imm 32
        imm = (w >> 10) & 0xFFF
        return "add      w%d, w%d, #0x%x" % (w & 31, (w >> 5) & 31, imm)
    return None


# 1. literal offsets and their pages
lit = {}
for k in KEYS:
    for off in find_literal(k):
        lit.setdefault(k, []).append(off)

want_pages = {}          # page -> list of (key, offset)
for k, offs in lit.items():
    for off in offs:
        want_pages.setdefault(off & ~0xFFF, []).append((k, off))

print("literals:")
for k in KEYS:
    print("  %-20s %s" % (k, ["0x%x" % o for o in lit.get(k, [])][:4]))

# 2. single pass: every adrp whose target page is one of ours, then
#    look ahead 16 instructions for add with the literal's low 12 bits
sites = []               # (instr_off, key, off)
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
    for back in range(1, 17):
        off2 = pc + back * 4
        if off2 + 4 > len(data):
            break
        w2 = struct.unpack_from("<I", data, off2)[0]
        if (w2 & 0xFF800000) in (0x91000000, 0x11000000):
            imm12 = (w2 >> 10) & 0xFFF
            for (k, lo) in want_pages[page]:
                if imm12 == (lo & 0xFFF):
                    sites.append((off2, k, lo))

print("\nsites: %d" % len(sites))

# 3. cluster by proximity: regions where >=3 distinct keys are used
sites.sort()
clusters = []
cur = []
for s in sites:
    if cur and s[0] - cur[-1][0] > 0x800:
        if len(cur) >= 3:
            clusters.append(cur)
        cur = []
    cur.append(s)
if len(cur) >= 3:
    clusters.append(cur)

print("clusters with >=3 address keys: %d" % len(clusters))
for c in clusters[:6]:
    keys = sorted(set(k for _, k, _ in c))
    print("\n== region 0x%x..0x%x keys=%s"
          % (c[0][0], c[-1][0], keys))
    lo = max(0, c[0][0] - 0x40)
    hi = min(len(data) - 4, c[-1][0] + 0x60)
    for a in range(lo & ~3, hi, 4):
        w = struct.unpack_from("<I", data, a)[0]
        d = decode(a, w)
        if d:
            mark = ">>" if any(a == s[0] for s in c) else "  "
            print("%s 0x%08x  %s" % (mark, a, d))
