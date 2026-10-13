#!/usr/bin/env python3
"""scan_mov6.py -- find `mov wN,#6` (movz) or `orr wN,wzr,#6` followed within
4 insns by `str wN,[xM...]`, restricted to a Ghidra range."""
import struct
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
lo = int(sys.argv[1], 16) - GHI if len(sys.argv) > 1 else 0
hi = int(sys.argv[2], 16) - GHI if len(sys.argv) > 2 else 0xFFFFFFFF
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
n = len(text)
for i in range(0, n - 20, 4):
    pc = tv + i
    if pc < lo or pc > hi:
        continue
    w = struct.unpack_from("<I", text, i)[0]
    is_movz = (w & 0xFF800000) == 0x52800000 and ((w >> 5) & 0x1F) == 31 \
        and ((w >> 5) & 0x3FF) == 0 and (w & 0x1F) and (w >> 20 & 0x3FF) == 6
    # simpler: decode with capstone only on candidates
    if not is_movz:
        if (w & 0xFF800000) != 0x52800000:
            continue
    insns = list(md.disasm(text[i:i + 20], pc + GHI))
    if not insns:
        continue
    ins0 = insns[0]
    if ins0.mnemonic != "mov" or ins0.op_str.split(", ")[-1] != "#6":
        continue
    rd = ins0.op_str.split(", ")[0]
    if not rd.startswith("w"):
        continue
    for ins in insns[1:]:
        t = ins.op_str.replace(" ", "")
        if ins.mnemonic == "str" and t.startswith(rd + ",["):
            print("0x%08x  %s %s ; 0x%08x  %s %s"
                  % (ins0.address, ins0.mnemonic, ins0.op_str,
                     ins.address, ins.mnemonic, ins.op_str))
            break
        if ins.mnemonic in ("bl", "blr", "ret"):
            break
