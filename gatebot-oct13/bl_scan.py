#!/usr/bin/env python3
"""bl_scan.py -- find every `bl` instruction in .text that calls a target VA.

usage: python bl_scan.py <libUE4.so> <target_va_hex>

`bl` is PC-relative (imm26), so adrp/xref tools miss it.  This scans the
whole executable section for the encoding.  Findings = direct callers of a
function (serializers, builders, ctors).
"""
import struct
import sys


def main():
    path, target = sys.argv[1], int(sys.argv[2], 16)
    with open(path, "rb") as f:
        b = f.read(0x40)
    e_shoff = struct.unpack_from("<Q", b, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", b, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", b, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", b, 0x3E)[0]
    with open(path, "rb") as f:
        f.seek(e_shoff)
        sh = f.read(e_shnum * e_shentsize)
    str_off = struct.unpack_from("<Q", sh, e_shstrndx * e_shentsize + 24)[0]
    str_sz = struct.unpack_from("<Q", sh, e_shstrndx * e_shentsize + 32)[0]
    with open(path, "rb") as f:
        f.seek(str_off)
        names = f.read(str_sz)
    hits = []
    with open(path, "rb") as f:
        for i in range(e_shnum):
            off = i * e_shentsize
            name, typ, flags, addr, offset, size = struct.unpack_from(
                "<IIQQQQ", sh, off)
            sname = names[name:].split(b"\0", 1)[0]
            if sname != b".text":
                continue
            f.seek(offset)
            chunk = f.read(size)
            for j in range(0, len(chunk) - 4, 4):
                w = struct.unpack_from("<I", chunk, j)[0]
                if (w >> 26) != 0x25:          # 100101 = bl
                    continue
                imm = w & 0x3FFFFFF
                if imm & 0x2000000:
                    imm -= 0x4000000
                pc = addr + j
                if pc + imm * 4 == target:
                    hits.append(pc)
    if not hits:
        print("0 callers of 0x%x" % target)
    for pc in hits:
        print("caller 0x%x  ->  0x%x" % (pc, target))


if __name__ == "__main__":
    main()
