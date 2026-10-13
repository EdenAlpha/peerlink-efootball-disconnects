#!/usr/bin/env python3
"""wss_table.py -- find pointer-table entries for 'wss://' and the WS
upgrade log strings, then their xrefs.

vaddr == file offset in this image (verified by earlier adrp xrefs), so
rodata pointers store the file offset as u64/u32.
"""
import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()

targets = {
    0xb69e7d: "wss://",
    0xc15169: "WebSockets upgrade: %d",
    0xb42653: "WebSocket; mask %02x%02x%02x%02x",
    0xa11b5a: "websocket, decoded %s [%s%s payload=%ld/%ld]",
    0xaa8b08: "Sec-WebSocket-Key",
}

for t, label in targets.items():
    for width in (8, 4):
        pat = struct.pack("<Q" if width == 8 else "<I", t)
        offs = []
        st = 0
        while True:
            i = data.find(pat, st)
            if i < 0:
                break
            offs.append(i)
            st = i + 1
        if offs:
            print("%-40s u%d refs: %s" % (label, width * 8,
                                          ["0x%x" % o for o in offs][:10]))
            break
    else:
        print("%-40s NO pointer-table refs" % label)
