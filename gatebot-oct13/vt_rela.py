#!/usr/bin/env python3
"""vt_rela.py -- recover vtable contents of the old binary from .rela.dyn:
   for each slot of the request-class vtable (Ghidra 0x09926d08) find the
   R_AARCH64_RELATIVE addend (= function vaddr), then disassemble each
   method with string annotation to recover request-body keys."""
import re
import struct
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so")
VT_G = 0x09926d08
GHI = 0x100000
NSLOT = 48
want_lo = VT_G - GHI                     # vaddr == file offset (old .so)

with open(SO, "rb") as f:
    e = f.read(64)
    assert e[:4] == b"\x7fELF" and e[4] == 2
    shoff, = struct.unpack_from("<Q", e, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", e, 0x3a)
    f.seek(shoff)
    sh = f.read(shentsize * shnum)

    def sdesc(i):
        off = i * shentsize
        name, typ, flags, addr, offset, size, link, info, align, entsize = \
            struct.unpack_from("<IIQQQQIIQQ", sh, off)
        return typ, offset, size, entsize

    # shstrtab
    typ, stroff, strsz, _ = sdesc(shstrndx)
    f.seek(stroff)
    strtab = f.read(strsz)

    rela = None
    for i in range(shnum):
        typ, offset, size, entsize = sdesc(i)
        if typ == 4 and entsize == 24:            # SHT_RELA, biggest wins
            if rela is None or size > rela[2]:
                rela = (typ, offset, size, entsize)

    _, roff, rsize, _ = rela
    f.seek(roff)
    rela_data = f.read(rsize)

slots = [None] * NSLOT
for k in range(0, rsize, 24):
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", rela_data, k)
    if want_lo <= r_offset < want_lo + 8 * NSLOT:
        slots[(r_offset - want_lo) // 8] = r_addend
print("filled slots: %d" % sum(s is not None for s in slots))
sys.stdout.flush()

def cstr(f, off, limit=80):
    f.seek(off)
    b = f.read(limit)
    if not b or not (0x20 <= b[0] <= 0x7e):
        return None
    s = b.split(b"\x00")[0]
    if len(s) < 3:
        return None
    try:
        t = s.decode("ascii")
    except UnicodeDecodeError:
        return None
    return t if all(0x20 <= ord(c) < 0x7f for c in t) else None

with open(SO, "rb") as f:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    page = {}
    for i, fn in enumerate(slots):
        if fn is None or not (0x10000 < fn < 0x9000000):
            continue
        f.seek(fn)
        code = f.read(0x500)
        keys, lines = [], []
        for insn in md.disasm(code, fn):
            ops = insn.op_str.split(", ")
            if insn.mnemonic == "adrp" and len(ops) == 2:
                m = re.search(r"#(-?0x[0-9a-f]+)", ops[1])
                if m:
                    page[ops[0]] = int(m.group(1), 16)
            elif insn.mnemonic in ("add", "ldr") and len(ops) >= 3:
                m = re.search(r"#(-?0x[0-9a-f]+)", ops[-1])
                if m and ops[1] in page:
                    s = cstr(f, page[ops[1]] + int(m.group(1), 16))
                    if s is not None:
                        keys.append(s)
                        lines.append("      0x%08x %-5s -> %r"
                                     % (insn.address, insn.mnemonic, s))
            if insn.mnemonic == "ret":
                break
        if keys:
            print("slot %2d fn=0x%08x (ghidra 0x%08x):" % (i, fn, fn + GHI))
            for ln in lines:
                print(ln)
            print()
