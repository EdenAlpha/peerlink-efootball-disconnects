#!/usr/bin/env python3
"""Find pointers to the crypto strings, because UE4 does not use ADRP+ADD.

four reason the simple scan gets zero: UE4 keeps constant strings in a
packed relocation table. At load time the linker writes the strings' real
virtual addresses into entries in .data/.rodata, and the code reads those
entries with an LDR from a nearby literal pool. The literal pool IS in the
executable segment, so when we find one it sits right next to the code that
uses the string.

Method, no judgement calls:
  1. take each string's real virtual address
  2. search the entire dump for that 64-bit value, little-endian
  3. each hit is a table entry = a pointer to our string
  4. report which region each pointer lives in

A pointer that lands inside the executable segment is a literal-pool entry,
i.e. it is loaded by an instruction immediately above it. That is the code
site we were looking for, found by address rather than by guessing a pattern.
"""
import mmap
import os
import re
import struct

D = r"C:\Users\Administrator\AppData\Local\Temp\2\artj\kgs-gappslive-36963768970\kgs\full"
FULL = os.path.join(D, "full.bin")
INDEX = os.path.join(D, "index.txt")
MAPS = os.path.join(D, "maps.txt")

WINDOWS = [
    # (label, string vaddr)
    ("KeyExchangeEncryptionKey", 0xf500ae8afebc),
    ("SessionKeyEncryptionKeyLength", 0xf500ae8afed5),
    ("SessionKeyEncryptionAlgorithm", 0xf500ae8fbc90),
    ("KeyExchangeEncryptionAlgorithm", 0xf500ae9ce776),
    ("RSA_PRIVATE_KEY", 0xf500ae9b9e86),
]

# the dump offsets of these strings, used for the 64-bit LE pointer search
for _l, _v in WINDOWS:
    pass

# executable range of libUE4.so for "is this pointer in a literal pool"
UE4_TEXT_LO = 0xf500b0641000
UE4_TEXT_HI = 0xf500b698a000


def load_index():
    regs = []
    with open(INDEX, errors="replace") as fh:
        for line in fh:
            p = line.split()
            if len(p) < 5:
                continue
            try:
                off = int(p[3])
            except ValueError:
                continue
            if off < 0:
                off += 1 << 32
            try:
                s, e = p[0].split("-")
            except ValueError:
                continue
            regs.append((off, int(s, 16), int(e, 16), p[1]))
    regs.sort()
    return regs


def vaddr_of(regs, pos):
    lo, hi = 0, len(regs) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        if regs[m][0] <= pos:
            if m + 1 >= len(regs) or regs[m + 1][0] > pos:
                off, s, e, perms = regs[m]
                delta = pos - off
                return (s + delta if 0 <= delta and s + delta < e else None), perms
            lo = m + 1
        else:
            hi = m - 1
    return None, None


def main():
    regs = load_index()
    f = open(FULL, "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    for label, tva in WINDOWS:
        needle = struct.pack("<Q", tva)
        print("\n=== pointers to %s (va 0x%x) ===" % (label, tva))
        hits = 0
        start = 0
        while True:
            i = mm.find(needle, start)
            if i < 0:
                break
            start = i + 1
            va, perms = vaddr_of(regs, i)
            if va is None:
                continue
            hits += 1
            where = perms or "?"
            intext = "IN-LIBUE4-TEXT" if UE4_TEXT_LO <= va < UE4_TEXT_HI else ""
            print("   ptr @ va 0x%x  [%s] %s" % (va, where, intext))
        if hits == 0:
            print("   (no 64-bit pointers found)")
    mm.close()
    f.close()


main()
