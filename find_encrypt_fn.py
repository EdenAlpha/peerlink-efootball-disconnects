#!/usr/bin/env python3
"""Find the function that writes the pes-custom-encrypt header, without Ghidra.

The literal is at file offset 0xad120e of libUE4.so. In AArch64, code reaches
it with ADRP+ADD (page + offset) or ADR. This scans .text for instructions
whose computed target lands within a small window of the literal, then
disassembles the enclosing function for the cipher call and its key argument.

Photocopier: read the key path out of the game's own code. Never guess it.
"""
import struct
import sys

SO = sys.argv[1] if len(sys.argv) > 1 else \
    r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
LIT = 0xAD120E
WIN = 0x3000

data = open(SO, "rb").read()
print("so bytes: %d" % len(data))

# --- minimal ELF parse for .text file range ---
assert data[:4] == b"\x7fELF"
is64 = data[4] == 2
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
segs = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags, p_off, p_vaddr = struct.unpack_from("<IIQQ", data, o)
    p_filesz = struct.unpack_from("<Q", data, o + 32)[0]
    segs.append((p_type, p_flags, p_off, p_vaddr, p_filesz))

# section headers for .text file offsets
e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
text_off = text_size = text_vaddr = None
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size = struct.unpack_from("<IIQQQQ", data, o)
    # resolved by content heuristic below instead of names (no strtab walk)
    pass

# Fallback: executable PT_LOADs are .text-ish. Find which file range holds code
# by looking for the known function prologue density is overkill; instead use
# the vaddr model from M22: file offset = vaddr - 0x4000 for .text.
text = None
for (t, fl, off, va, sz) in segs:
    if t == 1 and (fl & 1):
        print("exec seg: fileoff=0x%x vaddr=0x%x size=0x%x" % (off, va, sz))
        if text is None:
            text_off, text_size, text_vaddr = off, sz, va

print("using .text fileoff=0x%x size=0x%x vaddr=0x%x" % (text_off, text_size, text_vaddr))

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False

# literal's runtime address: rodata has offset==vaddr (M22), image slid by base.
# Work in FILE offsets: target file off = LIT.
refs = []
code = data[text_off:text_off + text_size]
n = len(code) // 4
for i in range(n):
    insn = struct.unpack_from("<I", code, i * 4)[0]
    op = (insn >> 24) & 0x1F
    # ADRP: 0x90000000 mask 0x9f000000
    if (insn & 0x9F000000) == 0x90000000:
        immhi = (insn >> 5) & 0x7FFFF
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        pc = text_off + i * 4
        target = (pc & ~0xFFF) + (imm << 12)
        if abs(target - LIT) < WIN:
            rd = insn & 0x1F
            refs.append((pc, "ADRP x%d -> 0x%x" % (rd, target)))
    # ADR: 0x10000000 mask 0x9f000000
    elif (insn & 0x9F000000) == 0x10000000:
        immhi = (insn >> 5) & 0x7FFFF
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        pc = text_off + i * 4
        target = pc + imm
        if abs(target - LIT) < WIN:
            rd = insn & 0x1F
            refs.append((pc, "ADR x%d -> 0x%x" % (rd, target)))

print("refs into literal window: %d" % len(refs))
for pc, d in refs[:20]:
    print("  file 0x%08x  %s" % (pc, d))
