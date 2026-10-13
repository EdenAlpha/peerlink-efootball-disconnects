#!/usr/bin/env python3
"""dis_range.py -- STR-annotated capstone disasm of an 11.1.0 range.

  python dis_range.py <ghidra_start_hex> <ghidra_end_hex> [outfile]

Ghidra = vaddr + 0x100000; .text file offset = vaddr - 0x4000.
Prints annotated string refs after writing the full disasm.
"""
import re
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
DUMP = (r"C:\Users\Administrator\Documents\Default Project\work"
        r"\ghidra_sgr\full1110\fulldump_out.txt")
TEXT_DELTA = 0x4000
GHI_DELTA = 0x100000

START_G = int(sys.argv[1], 16)
END_G = int(sys.argv[2], 16)
OUT = (sys.argv[3] if len(sys.argv) > 3 else
       r"C:\Users\Administrator\Documents\Default Project\work"
       r"\range.dis")

strs = {}
pat = re.compile(rb"^DATA ([0-9a-f]+) type=string len=\d+ val=(.*)$")
pat2 = re.compile(rb"^STR ([0-9a-f]+) ([^|]+?)(?: \||$)")
with open(DUMP, "rb") as f:
    for line in f:
        if line.startswith(b"DATA "):
            m = pat.match(line)
            if m:
                strs[int(m.group(1), 16)] = m.group(2).decode(
                    "utf-8", "replace").rstrip("\r\n")
        elif line.startswith(b"STR "):
            m = pat2.match(line)
            if m:
                strs.setdefault(int(m.group(1), 16), m.group(2).decode(
                    "utf-8", "replace").strip())

START = START_G - GHI_DELTA - TEXT_DELTA
with open(SO, "rb") as f:
    f.seek(START)
    code = f.read(END_G - START_G)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
page = {}
out = []
imm = re.compile(r"#(-?0x[0-9a-f]+)")
for insn in md.disasm(code, START + TEXT_DELTA):
    txt = "0x%08x  %-8s %s" % (insn.address, insn.mnemonic, insn.op_str)
    ann = ""
    ops = insn.op_str.split(", ")
    if insn.mnemonic == "adrp" and len(ops) == 2:
        m = imm.search(ops[1])
        if m:
            page[ops[0]] = int(m.group(1), 16)
    elif insn.mnemonic in ("add", "ldr") and len(ops) >= 3:
        m = imm.search(ops[-1])
        if m and ops[1] in page:
            addr = page[ops[1]] + int(m.group(1), 16) + GHI_DELTA
            if addr in strs:
                ann = "           ; STR 0x%x '%s'" % (addr, strs[addr])
    out.append(txt + ann)
open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("disasm lines: %d -> %s" % (len(out), OUT))
for ln in out:
    if "; STR" in ln:
        print(ln)
