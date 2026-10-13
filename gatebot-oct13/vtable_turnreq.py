#!/usr/bin/env python3
"""vtable_turnreq.py -- dump the CMD_GET_TURN_SERVER_LIST REQUEST vtable
(PTR_FUN_09926d08, old binary) and disassemble every virtual method with
string annotation, to recover the exact request-body keys.

Old binary: Ghidra = vaddr + 0x100000, vaddr == file offset.
"""
import re
import struct
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
      r"efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so")
VT_G = 0x09926d08              # request class primary vtable (Ghidra)
GHI = 0x100000
NSLOT = 48

def cstr(f, off, limit=80):
    try:
        f.seek(off)
        b = f.read(limit)
    except Exception:
        return None
    if not b or b[0] < 0x20 or b[0] > 0x7e:
        return None
    s = b.split(b"\x00")[0]
    if len(s) < 3:
        return None
    try:
        t = s.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not all(0x20 <= ord(c) < 0x7f for c in t):
        return None
    return t

with open(SO, "rb") as f:
    vt_off = VT_G - GHI
    f.seek(vt_off)
    slots = struct.unpack("<%dQ" % NSLOT, f.read(8 * NSLOT))

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    page = {}
    for i, fn in enumerate(slots):
        if not (0x10000 < fn < 0x9000000):
            continue
        f.seek(fn)
        code = f.read(0x400)
        lines = []
        keys = []
        for insn in md.disasm(code, fn):
            ops = insn.op_str.split(", ")
            if insn.mnemonic == "adrp" and len(ops) == 2:
                m = re.search(r"#(-?0x[0-9a-f]+)", ops[1])
                if m:
                    page[ops[0]] = int(m.group(1), 16)
            elif insn.mnemonic in ("add", "ldr") and len(ops) >= 3:
                m = re.search(r"#(-?0x[0-9a-f]+)", ops[-1])
                if m and ops[1] in page:
                    tgt = page[ops[1]] + int(m.group(1), 16)
                    s = cstr(f, tgt)
                    if s is not None:
                        keys.append(s)
                        lines.append("    0x%08x %s -> %r"
                                     % (insn.address, insn.mnemonic, s))
            if insn.mnemonic == "ret":
                break
        if keys:
            print("slot %2d  fn=0x%08x (ghidra 0x%08x)" % (i, fn, fn + GHI))
            for ln in lines:
                print(ln)
            print()
