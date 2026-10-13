#!/usr/bin/env python3
"""read_vtable.py -- read a vtable from the prev-update libUE4.so by Ghidra
address and resolve member function pointers to Ghidra addresses.

Address rule (prev update): Ghidra imageBase = ELF vaddr + 0x100000;
rodata: file offset == ELF vaddr.
"""
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
      r"\efootball-apk\native\lib\arm64-v8a\libUE4.so")

# sanity: "CmdSetGameResult.php" lives at Ghidra 00c8ee08 (rodata)
CHECK_STR = b"CmdSetGameResult.php"


def ghidra_to_off(gh):
    return gh - 0x100000


def main():
    data = open(SO, "rb").read()
    off = ghidra_to_off(0x00C8EE08)
    got = data[off:off + len(CHECK_STR)]
    print("rodata check @0x%08x: %r" % (off, got[:24]))
    if got != CHECK_STR:
        print("MISMATCH -- offset rule wrong; trying vaddr-0x4000")
    for base in (0x098D8CB8, 0x098D8C20, 0x098D8C68, 0x098D8C98,
                 0x098D8D00, 0x098D8D30, 0x098D8D50, 0x098CA6D8):
        o = ghidra_to_off(base)
        words = struct.unpack_from("<16Q", data, o)
        print()
        print("vtable @%08x (off %08x):" % (base, o))
        for i, w in enumerate(words):
            # function pointers sit in .text (ELF vaddr 0x2866500.. no, prev
            # update: .text ELF vaddr ~0x1000.. ; Ghidra 0x101000..0xA6AE320)
            if 0x100000 < w < 0xA000000:
                print("  +%2d  Ghidra %08x" % (i, w))
            else:
                print("  +%2d  %016x" % (i, w))


if __name__ == "__main__":
    main()
