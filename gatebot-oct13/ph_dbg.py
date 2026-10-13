import struct
SO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
with open(SO,"rb") as f:
    e = f.read(64)
    phoff, = struct.unpack_from("<Q", e, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", e, 0x36)
    f.seek(phoff)
    print("segments:")
    for i in range(phnum):
        d = f.read(phentsize)
        p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", d)
        if p_type == 1:
            print("  LOAD off=%x vaddr=%x filesz=%x memsz=%x flags=%d" % (p_off, p_vaddr, p_filesz, p_memsz, p_flags))
    # where is 0x08926d08?
    tgt = 0x08926d08
    f.seek(phoff)
    for i in range(phnum):
        d = f.read(phentsize)
        p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", d)
        if p_type == 1 and p_vaddr <= tgt < p_vaddr + p_memsz:
            print("vtable vaddr %x -> file off %x (delta %x)" % (tgt, p_off + (tgt - p_vaddr), p_vaddr - p_off))
