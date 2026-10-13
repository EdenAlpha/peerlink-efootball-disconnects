#!/usr/bin/env python3
"""old_dis.py -- STR-annotated capstone disasm of the OLD binary.
  python old_dis.py <ghidra_start_hex> <ghidra_end_hex> [outfile]
Old binary: Ghidra = vaddr + 0x100000; .text file offset = vaddr - 0x4000;
strings (rodata segment 1) file offset = vaddr = Ghidra - 0x100000.
"""
import re
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so")
TEXT_DELTA = 0x4000
GHI_DELTA = 0x100000

START_G = int(sys.argv[1], 16)
END_G = int(sys.argv[2], 16)
OUT = (sys.argv[3] if len(sys.argv) > 3 else
       r"C:\Users\Administrator\Documents\Default Project\work\old.dis")

start = START_G - GHI_DELTA - TEXT_DELTA
end = END_G - GHI_DELTA - TEXT_DELTA


def cstr(f, off, limit=96):
    f.seek(off)
    b = f.read(limit)
    if not b or not (0x20 <= b[0] <= 0x7e):
        return None
    s = b.split(b"\x00")[0]
    if len(s) < 2:
        return None
    try:
        t = s.decode("ascii")
    except UnicodeDecodeError:
        return None
    return t if all(0x20 <= ord(c) < 0x7f for c in t) else None


md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
lines = []
pages = {}
with open(SO, "rb") as f:
    f.seek(start)
    code = f.read(end - start)
    for insn in md.disasm(code, START_G):
        note = ""
        ops = insn.op_str.split(", ")
        if insn.mnemonic == "adrp" and len(ops) == 2:
            m = re.search(r"#(-?0x[0-9a-f]+)", ops[1])
            if m:
                pages[ops[0]] = int(m.group(1), 16)
        elif insn.mnemonic in ("add", "ldr") and len(ops) >= 3:
            m = re.search(r"#(-?0x[0-9a-f]+)", ops[-1])
            if m and ops[1] in pages:
                tgt = pages[ops[1]] + int(m.group(1), 16)
                s = cstr(f, tgt - GHI_DELTA)
                if s is not None:
                    note = "  ; STR 0x%08x %r" % (tgt, s)
        lines.append("0x%08x  %-8s %s%s" % (insn.address, insn.mnemonic,
                                            insn.op_str, note))

with open(OUT, "w", encoding="utf-8") as g:
    g.write("\n".join(lines) + "\n")
print("disasm lines: %d -> %s" % (len(lines), OUT))
for ln in lines:
    if "STR" in ln:
        print(ln)
