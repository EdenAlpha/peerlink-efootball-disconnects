#!/usr/bin/env python3
"""find_callers.py -- locate every direct BL/B to given Ghidra addresses.

fulldump_out.txt carries no call xrefs, so the only way to find who invokes
CMD_SET_GAME_RESULT's builders is to scan .text for the ARM64 branch encoding.

  python find_callers.py 078a0f7c 07895038 ...

Address rules (from dis_range.py):
    Ghidra = vaddr + 0x100000 ; .text vaddr = file offset + 0x4000
    => Ghidra = file_offset + 0x104000
Read-only.
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
TEXTOFF = 0x4000
# decomp range from fulldump: 0x0770001c - 0x0a6ae320 (Ghidra)
LO_G, HI_G = 0x07700000, 0x0a6b0000


def main():
    targets = {int(a, 16) for a in sys.argv[1:]}
    if not targets:
        print("usage: find_callers.py <ghidra_addr> ...")
        return 2

    lo = LO_G - GHI - TEXTOFF          # file offset of scan start
    hi = HI_G - GHI - TEXTOFF
    with open(SO, "rb") as f:
        f.seek(lo)
        data = f.read(hi - lo)
    print("scanned file [%#x, %#x) = %.1f MB of .text"
          % (lo, lo + len(data), len(data) / 1048576.0))

    hits = []
    for i in range(0, len(data) - 3, 4):
        w = struct.unpack_from("<I", data, i)[0]
        op = w & 0xFC000000
        if op != 0x94000000 and op != 0x14000000:      # BL / B only
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        addr = lo + i + GHI + TEXTOFF                  # Ghidra addr of insn
        tgt = addr + (imm << 2)
        if tgt in targets:
            hits.append((addr, tgt, "bl" if op == 0x94000000 else "b"))

    print("hits: %d" % len(hits))
    for addr, tgt, kind in sorted(hits):
        print("  %#010x  %s  -> %#010x" % (addr, kind, tgt))
    for t in sorted(targets):
        n = sum(1 for h in hits if h[1] == t)
        print("  target %#010x : %d caller(s)" % (t, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
