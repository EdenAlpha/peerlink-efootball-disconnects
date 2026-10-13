# dbg1110.py -- why zero STR annotations? inspect adrp/add forms + addr hits
import re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
DUMP = (r"C:\Users\Administrator\Documents\Default Project\work"
        r"\ghidra_sgr\full1110\fulldump_out.txt")
START_G, END_G = 0x7895324, 0x7896fd4

strs = {}
pat = re.compile(rb"^DATA ([0-9a-f]+) type=string len=\d+ val=(.*)$")
with open(DUMP, "rb") as f:
    for line in f:
        if line.startswith(b"DATA "):
            m = pat.match(line)
            if m:
                strs[int(m.group(1), 16)] = m.group(2).decode(
                    "utf-8", "replace").rstrip("\r\n")
print("strings: %d" % len(strs))

START = START_G - 0x100000
with open(SO, "rb") as f:
    f.seek(START)
    code = f.read(END_G - START_G)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
page, hits, shown = {}, 0, 0
imm = re.compile(r"#(-?0x[0-9a-f]+|-?\d+)")
for insn in md.disasm(code, START):
    ops = insn.op_str.split(", ")
    if insn.mnemonic == "adrp" and len(ops) == 2:
        m = imm.search(ops[1])
        if m:
            page[ops[0]] = ((insn.address & ~0xFFF)
                            + int(m.group(1), 16))
            if shown < 6:
                print("adrp 0x%x %s -> page 0x%x"
                      % (insn.address, insn.op_str, page[ops[0]]))
                shown += 1
    elif insn.mnemonic == "add" and len(ops) == 3:
        m = imm.search(ops[2])
        if m and ops[1] in page:
            addr = page[ops[1]] + int(m.group(1), 16)
            if addr in strs:
                hits += 1
                if hits <= 8:
                    print("HIT 0x%x -> 0x%x '%s'"
                          % (insn.address, addr, strs[addr]))
            elif hits == 0 and shown < 14:
                print("miss add 0x%x -> 0x%x"
                      % (insn.address, addr))
                shown += 1
print("total string hits: %d" % hits)
# sanity: is 'abnormalend_reason' 0xcdd7d3 in strs at all?
print("abnormalend_reason in strs:", 0x00cdd7d3 in strs)
print("nearby 0xcdd000 page keys:", sorted(a for a in strs
      if 0xcdd000 <= a < 0xcde000)[:10])
