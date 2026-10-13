#!/usr/bin/env python3
"""scan_cfg6a0b.py -- track `add xD,xN,#0x6a0` (or #0x58) forward through movs;
report ldr w?,[reg,#0x78|0x7c|0x80|0x84] (or #0..#0x3c for +0x58 base)."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
n = len(text)
TARGETS = {0x78, 0x7C, 0x80, 0x84}
for i in range(0, n - 4, 4):
    w = struct.unpack_from("<I", text, i)[0]
    if w & 0xFFC00000 != 0x91000000:
        continue
    imm = (w >> 10) & 0xFFF
    if imm not in (0x6A0, 0x58):
        continue
    rd = w & 0x1F
    rn = (w >> 5) & 0x1F
    addpc = tv + i
    alias = {rd}
    insns = list(md.disasm(text[i:i + 4 * 24], addpc + GHI))
    for ins in insns[1:]:
        t = ins.op_str.replace(" ", "")
        if ins.mnemonic == "mov" and t.count(",") == 1:
            d, s = t.split(",")[0], t.split(",")[1]
            if s[0] == "x" and s[1:].isdigit() and int(s[1:]) in alias \
               and d[0] == "x" and d[1:].isdigit():
                alias.add(int(d[1:]))
        elif ins.mnemonic == "ldr" and t.startswith("w"):
            if "[" not in t or "," not in t:
                continue
            mem = t[t.index("[") + 1:t.index("]")]
            base = mem.split(",")[0]
            if "#" not in t:
                continue
            off = t[t.rindex("#") + 1:]
            try:
                iv = int(off, 16)
            except ValueError:
                continue
            if base and base[0] == "x" and base[1:].isdigit() \
               and int(base[1:]) in alias:
                if (imm == 0x6A0 and iv in TARGETS) or \
                   (imm == 0x58 and iv <= 0x3C):
                    print("0x%08x add x%d,#%#x ; 0x%08x ldr w?,[x%s,#%#x]  (%s %s)"
                          % (addpc + GHI, rd, imm, ins.address, base, iv,
                             ins.mnemonic, ins.op_str))
                    break
