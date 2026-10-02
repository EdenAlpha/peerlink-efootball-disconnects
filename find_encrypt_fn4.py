#!/usr/bin/env python3
"""Stage 2c: track register values through split ADD sequences.

For each ADRP to page 0xad1000, symbolically follow the target register
through up to 12 following instructions (ADD imm, ADD shifted, MOV between
registers) and report any path that resolves exactly to 0xad120e.
"""
import struct

SO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
PAGE, LIT = 0xAD1000, 0xAD120E
data = open(SO, "rb").read()
TEXT_OFF, TEXT_SZ = 0x28253C0, 0x6347D80
code = data[TEXT_OFF:TEXT_OFF + TEXT_SZ]

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

n = len(code) // 4
found = 0
for i in range(n):
    insn = struct.unpack_from("<I", code, i * 4)[0]
    if (insn & 0x9F000000) != 0x90000000:
        continue
    imm = (((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 0x3)
    if imm & 0x100000:
        imm -= 0x200000
    pc = TEXT_OFF + i * 4
    if (pc & ~0xFFF) + (imm << 12) != PAGE:
        continue
    rd0 = insn & 0x1F
    # vals[reg] = known value or None
    vals = {rd0: PAGE}
    chunk = code[i * 4:(i + 13) * 4]
    for ins in md.disasm(chunk, pc):
        if ins.mnemonic == "add" and len(ins.operands) >= 3 and \
                ins.operands[0].type == 1 and ins.operands[1].type == 1:
            d, s = ins.operands[0].reg, ins.operands[1].reg
            # need reg numbers; use regex on op_str instead
            import re
            m = re.match(r"x(\d+), x(\d+), #(0x[0-9a-f]+|\d+)(, lsl #(\d+))?",
                         ins.op_str)
            if m and vals.get(int(m.group(2))) is not None:
                sh = int(m.group(5)) if m.group(5) else 0
                vals[int(m.group(1))] = vals[int(m.group(2))] + int(m.group(3), 0) * (1 << sh)
                if vals[int(m.group(1))] == LIT:
                    print("LITERAL USER at file 0x%08x via %s %s" % (pc, ins.mnemonic, ins.op_str))
                    # print the whole 13-insn window for context
                    for ins2 in md.disasm(chunk, pc):
                        print("    0x%08x  %-8s %s" % (ins2.address, ins2.mnemonic, ins2.op_str))
                    print()
                    found += 1
                    break
        elif ins.mnemonic == "mov" and len(ins.operands) == 2:
            import re
            m = re.match(r"x(\d+), x(\d+)", ins.op_str)
            if m and vals.get(int(m.group(2))) is not None:
                vals[int(m.group(1))] = vals[int(m.group(2))]
        # any branch/call ends reliable tracking, but keep bl targets
        if ins.mnemonic in ("bl", "blr", "b", "br", "ret", "cbz", "cbnz"):
            if ins.mnemonic in ("bl", "blr"):
                # check if any tracked reg == LIT at call time
                for r, v in vals.items():
                    if v == LIT:
                        print("LIT live in x%d at call 0x%08x %s %s (from ADRP 0x%08x)"
                              % (r, ins.address, ins.mnemonic, ins.op_str, pc))
                        found += 1
            break
print("total paths to literal:", found)
