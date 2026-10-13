import sys
so = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
# old binary: Ghidra = vaddr + 0x100000; vaddr == file offset
ghidra = [0x00ca32c4, 0x00bfc78d, 0x00ae010c, 0x00b4b8e8,
          0x00af87e8, 0x00c108cf, 0x00c55deb, 0x00cef7be,
          0x00b85325, 0x00c6929f, 0x00b00ba2, 0x00c8f664,
          0x00be3f6d, 0x00c1d91c, 0x00b9816d, 0x00b7725e]
with open(so, "rb") as f:
    for g in ghidra:
        off = g - 0x100000
        f.seek(off)
        b = f.read(48)
        s = b.split(b"\x00")[0]
        print("0x%08x -> %r" % (g, s.decode("utf-8", "replace")))
