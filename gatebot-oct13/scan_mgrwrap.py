#!/usr/bin/env python3
"""scan_mgrwrap.py -- find wrapper fns: bl getter(0x07e0afcc) ; ldr xN,[x0,#0x10]
; (mov x0,xN)? ; ret  -- i.e. functions returning the manager.
Prints Ghidra addrs; then find_callers can be used on them."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from xref2 import Elf

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
GHI = 0x100000
GETTER = 0x07e0afcc
e = Elf(SO)
_, _, _, tv, to, ts = e.sec(".text")
text = e.read(to, ts)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
n = len(text)
for i in range(0, n - 4, 4):
    w = struct.unpack_from("<I", text, i)[0]
    if w & 0xFC000000 != 0x94000000:
        continue
    off = w & 0x3FFFFFF
    if off & 0x2000000:
        off -= 0x4000000
    if tv + i + off != GETTER:
        continue
    insns = list(md.disasm(text[i:i + 4 * 10], tv + i + GHI))
    seen = None
    for ins in insns[1:]:
        t = ins.op_str.replace(" ", "")
        if ins.mnemonic == "ldr" and ",[x0,#0x10]" in t:
            seen = t.split(",")[0]
        elif ins.mnemonic == "mov" and seen and t == "x0," + seen:
            seen = "x0"
        elif ins.mnemonic == "ret" and seen == "x0":
            print("wrapper ends at 0x%08x (bl at 0x%08x)"
                  % (ins.address, tv + i + GHI))
            break
        elif ins.mnemonic in ("bl", "blr"):
            break
