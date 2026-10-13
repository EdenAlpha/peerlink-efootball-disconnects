#!/usr/bin/env python3
"""win_fn.py -- disassemble a window of an arm64 libUE4.so with capstone,
annotating adrp+add string loads.

  python win_fn.py <so-path> <start-hex> <len-hex> [base-hex]

base-hex = bias added to printed addresses (Ghidra dump addresses need
-0x100000 to get ELF vaddrs; pass 0 for ELF vaddr input).
vaddr->file offset resolved from PT_LOAD.
"""
import struct
import sys

import capstone

path, start, ln = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
bias = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0
buf = open(path, "rb").read()

(e_phoff,) = struct.unpack_from("<Q", buf, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", buf, 0x36)
loads = []
for i in range(e_phnum):
    p = struct.unpack_from("<IIQQQQQQ", buf, e_phoff + i * e_phentsize)
    if p[0] == 1:
        loads.append((p[2], p[3], p[5]))  # offset, vaddr, filesz


def v2f(v):
    for off, va, sz in loads:
        if va <= v < va + sz:
            return off + (v - va)
    return None


fo = v2f(start - bias)
if fo is None:
    print("vaddr 0x%x not in any LOAD" % (start - bias))
    sys.exit(1)

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False
code = buf[fo:fo + ln]

prev_adrp = {}  # reg -> page


def name_at(v):
    f = v2f(v)
    if f is None:
        return None
    s = buf[f:f + 64]
    out = b""
    for c in s:
        if 32 <= c < 127:
            out += bytes([c])
        else:
            break
    return out.decode() if len(out) >= 3 else None


for ins in md.disasm(code, start - bias):
    pc = ins.address
    txt = ins.mnemonic + " " + ins.op_str
    note = ""
    if ins.mnemonic == "adrp":
        reg = ins.op_str.split(",")[0]
        tgt = int(ins.op_str.split("#")[-1], 16)
        prev_adrp[reg] = tgt
    elif ins.mnemonic == "add" and ", #" in ins.op_str:
        parts = [p.strip() for p in ins.op_str.split(",")]
        if len(parts) == 3 and parts[2].startswith("#"):
            rd, rn = parts[0], parts[1].split(" ")[0]
            if rn in prev_adrp and parts[2].startswith("#0x"):
                tgt = prev_adrp[rn] + int(parts[2].lstrip("#"), 16)
                nm = name_at(tgt)
                if nm:
                    note = '  ; "%s" @0x%x' % (nm, tgt)
    print("  0x%08x  %-30s%s" % (pc + bias, txt, note))
