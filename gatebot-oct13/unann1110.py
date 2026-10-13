# unann1110.py -- list every adrp+add target in the 11.1.0 serializer
# that was NOT annotated, reading the bytes straight from the binary.
# Anything printable = a key the annotator missed (dump string table gaps).
import re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native1110\libUE4.so")
DIS = r"C:\Users\Administrator\Documents\Default Project\work\sgr_enc1110.dis"
START_G, END_G = 0x7895324, 0x7896fd4
TEXT_DELTA, GHI_DELTA = 0x4000, 0x100000

raw = open(DIS, encoding="utf-8").read().splitlines()
annotated = set()
for ln in raw:
    m = re.match(r"0x([0-9a-f]+)\s+add.*; STR 0x([0-9a-f]+)", ln)
    if m:
        annotated.add(int(m.group(2), 16))

f = open(SO, "rb")
code = f.read()[START_G - GHI_DELTA - TEXT_DELTA:
                START_G - GHI_DELTA - TEXT_DELTA + END_G - START_G]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
page, imm = {}, re.compile(r"#(-?0x[0-9a-f]+)")
misses = []
for insn in md.disasm(code, START_G - GHI_DELTA):   # vaddr base
    ops = insn.op_str.split(", ")
    if insn.mnemonic == "adrp" and len(ops) == 2:
        m = imm.search(ops[1])
        if m:
            page[ops[0]] = int(m.group(1), 16)
    elif insn.mnemonic == "add" and len(ops) == 3:
        m = imm.search(ops[2])
        if m and ops[1] in page:
            addr = page[ops[1]] + int(m.group(1), 16)   # vaddr
            if addr + GHI_DELTA not in annotated and addr < 0x28624F8:
                f.seek(addr)   # segment1 rodata: file offset == vaddr
                b = f.read(48)
                end = b.find(b"\x00")
                s = b[:end] if 0 < end <= 40 else None
                if s and all(0x20 <= c < 0x7f for c in s):
                    misses.append((insn.address, addr, s.decode()))
for pc, addr, s in misses:
    print("0x%08x -> 0x%x  %r" % (pc, addr, s))
print("unannotated string targets: %d" % len(misses))
