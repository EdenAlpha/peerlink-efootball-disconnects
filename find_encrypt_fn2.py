#!/usr/bin/env python3
"""Stage 2: functions referencing the pes-custom-encrypt literal page.

Page of the literal (file off 0xad120e) is 0xad1000. Find ADRP targeting
exactly that page, read the following ADD for the exact offset, keep only the
ones that resolve to 0xad120e itself, then disassemble the enclosing function
looking for the cipher call (BL) and its key argument setup.
"""
import struct
import sys

SO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
PAGE = 0xAD1000
LIT = 0xAD120E

data = open(SO, "rb").read()
TEXT_OFF, TEXT_SZ = 0x28253C0, 0x6347D80
code = data[TEXT_OFF:TEXT_OFF + TEXT_SZ]

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

# pass 1: ADRP to our page
hits = []
n = len(code) // 4
for i in range(n):
    insn = struct.unpack_from("<I", code, i * 4)[0]
    if (insn & 0x9F000000) == 0x90000000:
        imm = (((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 0x3)
        if imm & 0x100000:
            imm -= 0x200000
        pc = TEXT_OFF + i * 4
        if (pc & ~0xFFF) + (imm << 12) == PAGE:
            hits.append((pc, insn & 0x1F))

print("ADRP to page 0xad1000: %d" % len(hits))

# pass 2: next ADD gives exact literal; keep 0xad120e
exact = []
for pc, rd in hits:
    i = (pc - TEXT_OFF) // 4
    if i + 1 >= n:
        continue
    nxt = struct.unpack_from("<I", code, (i + 1) * 4)[0]
    # ADD (immediate) 0x91000000, rd==rn, imm12
    if (nxt & 0xFF000000) == 0x91000000:
        rd2, rn = nxt & 0x1F, (nxt >> 5) & 0x1F
        imm12 = (nxt >> 10) & 0xFFF
        if rd2 == rn == rd and PAGE + imm12 == LIT:
            exact.append(pc)

print("resolving exactly to 0xad120e: %d" % len(exact))
for pc in exact[:10]:
    print("  file 0x%08x" % pc)

# pass 3: disassemble +-400 bytes around the first hit, show calls
if exact:
    pc = exact[0]
    start = max(TEXT_OFF, pc - 400)
    end = min(TEXT_OFF + TEXT_SZ, pc + 400)
    chunk = data[start:end]
    print()
    print("--- disassembly around file 0x%08x ---" % pc)
    for ins in md.disasm(chunk, start):
        mark = "  <-- LIT" if start <= pc < start + len(chunk) and ins.address == pc else ""
        if ins.mnemonic in ("bl", "blr", "adrp", "adr", "add", "mov", "ret"):
            print("  0x%08x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
