#!/usr/bin/env python3
"""Map crypto strings to virtual addresses and find the code that uses them.

The dump's file offsets are cumulative across regions, so a dump offset is not
a library offset. index.txt is the join: field[0] is the vaddr range and
field[3] is the dump file offset. That turns a dump position into a real
virtual address, which is what ADRP/ADD xrefs target.

Then for each interesting string we scan the executable segment for the
standard AArch64 address materialisation:

    ADRP xN, page_of_target
    ADD  xN, xN, #offset_in_page

which is how every reference to a .rodata literal is made. Matching it gives
candidate code sites without any pattern guessing.
"""
import mmap
import os
import struct
import sys

D = r"C:\Users\Administrator\AppData\Local\Temp\2\artj\kgs-gappslive-36963768970\kgs\full"
FULL = os.path.join(D, "full.bin")
INDEX = os.path.join(D, "index.txt")
MAPS = os.path.join(D, "maps.txt")

TARGETS = [
    b"KeyExchangeEncryptionKey",
    b"SessionKeyEncryptionKeyLength",
    b"SessionKeyEncryptionAlgorithm",
    b"KeyExchangeEncryptionAlgorithm",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"pes-custom-encrypt",
    b"sign=",
    b"AES256",
]


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
            regs.append((off, int(s, 16), int(e, 16), p[1], p[2][:40]))
    regs.sort()
    return regs


def region_of(regs, pos):
    lo, hi = 0, len(regs) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        if regs[m][0] <= pos:
            if m + 1 >= len(regs) or regs[m + 1][0] > pos:
                return regs[m]
            lo = m + 1
        else:
            hi = m - 1
    return None


def vaddr_of(regs, pos):
    r = region_of(regs, pos)
    if not r:
        return None, None
    off, s, e, perms, name = r
    delta = pos - off
    if delta < 0 or s + delta > e:
        return None, r
    return s + delta, r


def load_exec_segments(maps):
    """Executable segments: (vaddr_start, vaddr_end, file_offset)."""
    segs = []
    with open(MAPS, errors="replace") as fh:
        for line in fh:
            p = line.split()
            if len(p) < 5:
                continue
            rng, perms, fo = p[0], p[1], p[2]
            if "x" not in perms:
                continue
            try:
                s, e = rng.split("-")
                fo = int(fo, 16)
            except ValueError:
                continue
            segs.append((int(s, 16), int(e, 16), fo))
    segs.sort()
    return segs


def find_targets(mm):
    """Return [(label, vaddr, dump_off)] for each string occurrence."""
    out = []
    pos = 0
    # scan each target across the whole dump
    for pat in TARGETS:
        start = 0
        while True:
            i = mm.find(pat, start)
            if i < 0:
                break
            out.append((pat.decode("latin1"), i))
            start = i + 1
    return out


def adrp_page(insn, pc):
    """Page address an ADRP at pc produces, or None."""
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def add_imm(insn):
    """(Rd, Rn, imm12) for a 64-bit ADD immediate, else None."""
    if (insn & 0xFFC00000) != 0x91000000:
        return None
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    return rd, rn, imm12


def scan_xrefs(mm, text_va, text_fileoff, text_size, target_va):
    """Find ADRP+ADD pairs in the text segment that form target_va."""
    hits = []
    page = target_va & ~0xFFF
    off = target_va & 0xFFF
    end = text_fileoff + text_size
    # only look at instructions; step 4 bytes
    base_va = text_va
    n = text_size // 4
    # read the whole text chunk once
    chunk = mm[text_fileoff:end]
    for k in range(n - 1):
        pc = base_va + k * 4
        a = struct.unpack_from("<I", chunk, k * 4)[0]
        if (a & 0x9F000000) != 0x90000000:
            continue
        if adrp_page(a, pc) != page:
            continue
        rd_adrp = a & 0x1F
        # look ahead a few instructions for ADD rd, rd, #off
        for j in range(1, 8):
            b = struct.unpack_from("<I", chunk, (k + j) * 4)[0]
            ai = add_imm(b)
            if not ai:
                continue
            rd, rn, imm12 = ai
            if rn == rd_adrp and rd == rd_adrp and imm12 == off:
                hits.append((pc, pc + j * 4))
                break
    return hits


def main():
    regs = load_index()
    segs = load_exec_segments(MAPS)
    print("index regions: %d" % len(regs))
    print("executable segments:")
    for s, e, fo in segs:
        print("  va 0x%x-0x%x  fileoff 0x%x  size 0x%x" % (s, e, fo, e - s))

    f = open(FULL, "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    found = find_targets(mm)
    print("\n=== target locations ===")
    seen = set()
    resolved = []
    for label, dump_off in found:
        va, r = vaddr_of(regs, dump_off)
        if va is None:
            print("  %-34s dump 0x%x -> UNMAPPED" % (label, dump_off))
            continue
        key = (label, va)
        if key in seen:
            continue
        seen.add(key)
        perms = r[3]
        print("  %-34s dump 0x%x -> va 0x%x  [%s]" % (label, dump_off, va, perms))
        resolved.append((label, va))

    print("\n=== code xrefs into each target ===")
    for label, tva in resolved:
        print("-- %s @ 0x%x" % (label, tva))
        n = 0
        for ts, te, tfo in segs:
            if not ("x" in "x"):
                continue
            try:
                hits = scan_xrefs(mm, ts, tfo, te - ts, tva)
            except Exception as e:
                print("     scan failed: %s" % e)
                continue
            for adrp_pc, add_pc in hits:
                n += 1
                if n <= 12:
                    print("     xref at 0x%x (adrp) / 0x%x (add)" % (adrp_pc, add_pc))
        print("     total xrefs: %d" % n)

    mm.close()
    f.close()


if __name__ == "__main__":
    main()
