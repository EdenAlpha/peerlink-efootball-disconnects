#!/usr/bin/env python3
"""aps2_try.py -- find the correct APS2 framing by scoring candidate parses.

Invariants: (1) ends exactly at section end, (2) offsets non-decreasing and
8-aligned, (3) types in the valid dynamic set, (4) addends < 0x10000000.

Variants:
  V1 bionic:      group=[size][delta]; entry(j0)=[info][+add]; (j>0)=[off][info][+add]
  V2 j0-off:      as V1 but j0 also pops an offset delta
  V3 all-add:     V1 with addend popped for every entry (not just RELATIVE)
  V4 add-first:   entry=[off][+add if RELATIVE][info]
  V5 rel-only-raw:V1 but info types compared raw (no &0xffffffff)
"""
import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")
data = open(SO, "rb").read()

(e_shoff,) = struct.unpack_from("<Q", data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
shs = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
       for i in range(e_shnum)]
shstr = shs[e_shstrndx]
_strtab = data[shstr[4]:shstr[4] + shstr[5]]


def nm(off):
    end = _strtab.find(b"\x00", off)
    return _strtab[off:end].decode(errors="replace")


secs = {nm(s[0]): s for s in shs}
rela = secs[".rela.dyn"]
rela_off, rela_sz = rela[4], rela[5]
assert data[rela_off:rela_off + 4] == b"APS2"
START = rela_off + 4
END = rela_off + rela_sz
print("stream 0x%x..0x%x (%d bytes)" % (START, END, END - START))

VALID = {0, 257, 258, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032}


class Dec:
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


def parse(variant):
    d = Dec(data, START)
    n = good = add_ok = 0
    mono = aligned = True
    r_off = 0
    r_add = 0
    prev = -1
    samples = []
    try:
        while d.pos < END:
            size = d.u()
            delta = d.u()
            if size == 0 or size > 3_000_000:
                return None
            r_off += delta
            for j in range(size):
                if variant == "V2" and j == 0:
                    r_off += d.u()
                if j != 0:
                    r_off += d.u()
                if variant == "V4":
                    peek = d.s()  # addend comes before info in this variant
                    r_add += peek
                    info = d.u()
                else:
                    info = d.u()
                    if variant == "V3" or (info & 0xFFFFFFFF) == 1027:
                        r_add += d.s()
                if r_off < prev:
                    mono = False
                prev = r_off
                if r_off & 7:
                    aligned = False
                if 0 <= r_add < 0x10000000:
                    add_ok += 1
                t = info & 0xFFFFFFFF
                if t in VALID:
                    good += 1
                if n < 8:
                    samples.append((r_off, t, r_add))
                n += 1
                if n > 3_000_000:
                    return None
        if n == 0:
            return None
        return dict(n=n, t=good / n, mono=mono, align=aligned,
                    add=add_ok / n, exact=(d.pos == END), s=samples,
                    endpos=d.pos)
    except (IndexError, OverflowError):
        return None


for v in ("V1", "V2", "V3", "V4"):
    st = parse(v)
    if st is None:
        print("%s: parse failed" % v)
        continue
    score = (100 * st["exact"] + 50 * st["mono"] + 50 * st["align"]
             + int(100 * st["t"]))
    print("score=%4d %s | n=%d type_ok=%.2f mono=%s align=%s add_ok=%.2f "
          "exact=%s endpos=0x%x"
          % (score, v, st["n"], st["t"], st["mono"], st["align"], st["add"],
             st["exact"], st["endpos"]))
    print("    first:", [("0x%x" % o, t, "0x%x" % a)
                         for o, t, a in st["s"][:6]])
