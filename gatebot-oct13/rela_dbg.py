import struct
SO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
with open(SO,"rb") as f:
    e = f.read(64)
    shoff, = struct.unpack_from("<Q", e, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", e, 0x3a)
    f.seek(shoff); sh = f.read(shentsize*shnum)
    def sdesc(i):
        return struct.unpack_from("<IIQQQQIIQQ", sh, i*shentsize)
    typ, stroff, strsz = sdesc(shstrndx)[0], sdesc(shstrndx)[4], sdesc(shstrndx)[5]
    f.seek(stroff); strtab = f.read(strsz)
    for i in range(shnum):
        name, t, flags, addr, off, size, link, info, align, entsize = sdesc(i)
        nm = strtab[name:strtab.index(b"\x00", name)].decode()
        if t in (4, 9):  # RELA / REL
            print(i, nm, "type", t, "off", hex(off), "size", hex(size), "entsize", entsize)
    # sample entries of the first RELA
    for i in range(shnum):
        name, t, flags, addr, off, size, link, info, align, entsize = sdesc(i)
        if t == 4 and entsize == 24:
            f.seek(off); d = f.read(48)
            for k in range(0, 48, 24):
                o, inf, add = struct.unpack_from("<QQq", d, k)
                print("  entry r_offset=%x info=%x addend=%x" % (o, inf, add))
            break
