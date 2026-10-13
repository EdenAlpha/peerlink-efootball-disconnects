#!/usr/bin/env python3
"""aps2.py -- parse packed Android relocations (SHT_ANDROID_RELA) in libUE4.so.

usage:
  python aps2.py <libUE4.so> --addend <va_hex>   # slots filled with a function
  python aps2.py <libUE4.so> --offset <va_hex>   # who fills this address
  python aps2.py <libUE4.so> --vtable <base_hex> [--size 0x200]

SHT_ANDROID_RELA (sh_type 0x6ffffffa) entries are 24-byte {offset, info,
addend}: runtime writes *offset = load_bias + addend.  The vtables are zero
in-file and filled by these at load, so this is the only way to read the
function->slot mapping offline.
"""
import struct
import sys


def load_relocs(path):
    with open(path, "rb") as f:
        hdr = f.read(0x40)
        e_shoff = struct.unpack_from("<Q", hdr, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", hdr, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", hdr, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", hdr, 0x3E)[0]
        f.seek(e_shoff)
        sh = f.read(e_shnum * e_shentsize)
        stroff = struct.unpack_from("<Q", sh, e_shstrndx * e_shentsize + 24)[0]
        strsz = struct.unpack_from("<Q", sh, e_shstrndx * e_shentsize + 32)[0]
        f.seek(stroff)
        names = f.read(strsz)
        out = []
        for i in range(e_shnum):
            off = i * e_shentsize
            name, typ, flags, addr, offset, size = struct.unpack_from(
                "<IIQQQQ", sh, off)
            if typ not in (0x6FFFFFFA, 0x60000002):
                continue
            sname = names[name:].split(b"\0", 1)[0].decode("latin1")
            f.seek(offset)
            blob = f.read(size)
            if blob[:4] == b"APS2":
                ents = unpack_aps2(blob[4:])
            else:                                  # plain 24-byte RELA
                n = len(blob) // 24
                ents = [struct.unpack_from("<QQq", blob, k * 24)
                        for k in range(n)]
            out.append((sname, offset, size, ents))
    return out


def unpack_aps2(b):
    """AOSP packed_relocations format -> [(offset, info, addend)]."""
    pos = 0
    n = len(b)

    def uleb():
        nonlocal pos
        result = shift = 0
        while True:
            byte = b[pos]
            pos += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7

    def sleb():
        nonlocal pos
        result = shift = 0
        while True:
            byte = b[pos]
            pos += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if byte & 0x40:
                    result -= 1 << shift
                return result

    out = []
    offset = 0
    addend = 0
    while pos < n:
        group_size = uleb()
        offset += sleb()
        flags = uleb()
        r_type = flags >> 1
        if flags & 1:
            addend += sleb()                       # constant group addend
        for _ in range(group_size):
            if pos >= n:
                break
            offset += uleb()
            if not flags & 1:
                addend += sleb()
            out.append((offset, r_type, addend))
    return out


def main():
    path = sys.argv[1]
    mode = sys.argv[2]
    secs = load_relocs(path)
    total = sum(len(e) for *_, e in secs)
    print("sections: %s  entries: %d"
          % ([(s, hex(sz)) for s, _, sz, _ in secs], total))
    if mode == "--addend":
        want = int(sys.argv[3], 16)
        for sname, _, _, ents in secs:
            for off, info, add in ents:
                if add == want:
                    print("slot offset=0x%x info=0x%x addend=0x%x (%s)"
                          % (off, info, add, sname))
    elif mode == "--offset":
        want = int(sys.argv[3], 16)
        for sname, _, _, ents in secs:
            for off, info, add in ents:
                if off == want:
                    print("offset=0x%x info=0x%x addend=0x%x (%s)"
                          % (off, info, add, sname))
    elif mode == "--vtable":
        base = int(sys.argv[3], 16)
        size = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0x200
        for sname, _, _, ents in secs:
            for off, info, add in ents:
                if base <= off < base + size:
                    print("0x%x: 0x%x" % (off, add))


if __name__ == "__main__":
    main()
