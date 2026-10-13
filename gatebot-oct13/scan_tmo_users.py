#!/usr/bin/env python3
"""scan_tmo_users.py -- for every `bl FUN_07f0afcc` (settings singleton getter),
watch the next 48 instructions for `ldr xN,[x0,#0x10]` and then a
`ldr wM,[xN,#0x718|0x71c|0x720|0x724]`. Prints Ghidra addrs."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
GETTER = 0x07e0afcc            # vaddr of FUN_07f0afcc
WANT = {0x718, 0x71c, 0x720, 0x724}
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
n = len(text)
for i in range(0, n - 4, 4):
    w = struct.unpack_from("<I", text, i)[0]
    if w & 0xFC000000 != 0x94000000:          # bl
        continue
    off = w & 0x3FFFFFF
    if off & 0x2000000:
        off -= 0x4000000
    if tv + i + off != GETTER:
        continue
    pc0 = tv + i
    tracked = None
    insns = list(md.disasm(text[i:i + 4 * 48], pc0 + GHI))
    for ins in insns:
        t = ins.op_str.replace(" ", "")
        if ins.mnemonic == "ldr" and t.startswith("x") and ",[x0,#0x10]" == t[t.index(","):]:
            tracked = t[:t.index(",")]
        elif tracked and ins.mnemonic == "ldr" and t.startswith("w"):
            base = t[t.index("[") + 1:t.index(",")]
            imm = t[t.rindex("#") + 1:]
            try:
                iv = int(imm, 16)
            except ValueError:
                continue
            if base == tracked and iv in WANT:
                print("caller 0x%08x -> reads [%s,#0x%x] at 0x%08x  %s %s"
                      % (pc0 + GHI, tracked, iv, ins.address,
                         ins.mnemonic, ins.op_str))
