#!/usr/bin/env python3
"""Stage 2b: what follows the 149 ADRPs to the literal page?"""
import struct

SO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
PAGE = 0xAD1000
data = open(SO, "rb").read()
TEXT_OFF, TEXT_SZ = 0x28253C0, 0x6347D80
code = data[TEXT_OFF:TEXT_OFF + TEXT_SZ]

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

n = len(code) // 4
shown = 0
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
    # disassemble next 6 insns
    chunk = code[i * 4:(i + 7) * 4]
    print("--- file 0x%08x ---" % pc)
    for ins in md.disasm(chunk, pc):
        print("  0x%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    shown += 1
    if shown >= 8:
        break
