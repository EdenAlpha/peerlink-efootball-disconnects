#!/usr/bin/env python3
"""hb1110.py -- annotated disasm of the 11.1.0 CMD_HEARTBEAT_GRPC area.

Answers: does the real heartbeat body carry match context (game_id /
room_id) during a match, or is it a bare user/session envelope?
Range: FUN_07cef5d4 (612B, xrefs CMD_HEARTBEAT_GRPC) through
FUN_07cefddc+316 (the .php-name refs) -- covers body builders
FUN_07cefbf4 / FUN_07cefc8c (heartbeat_interval_msec xrefs).
Address math (same as dis1110.py): Ghidra = vaddr + 0x100000,
.text file = vaddr - 0x4000.
"""
import re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
DUMP = (r"C:\Users\Administrator\Documents\Default Project\work"
        r"\ghidra_sgr\full1110\fulldump_out.txt")
OUT = (r"C:\Users\Administrator\Documents\Default Project\work"
       r"\hb1110.dis")
START_G, END_G = 0x7cef5d4, 0x7ceff20       # Ghidra addrs
TEXT_DELTA = 0x4000
GHI_DELTA = 0x100000

# string table: DATA (capped) + STR lines
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
print("strings: %d" % len(strs))

START = START_G - GHI_DELTA - TEXT_DELTA     # file offset
with open(SO, "rb") as f:
    f.seek(START)
    code = f.read(END_G - START_G)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
page = {}
out = []
imm = re.compile(r"#(-?0x[0-9a-f]+)")
for insn in md.disasm(code, START + TEXT_DELTA):   # base = vaddr
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

print("\n--- annotated string refs in order ---")
for ln in out:
    if "; STR" in ln:
        print(ln)
