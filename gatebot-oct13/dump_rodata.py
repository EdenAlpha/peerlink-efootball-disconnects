#!/usr/bin/env python3
"""dump_rodata.py -- print printable strings around an address in the
prev-update libUE4.so (rodata: file offset = Ghidra addr - 0x100000)."""
import re
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
      r"\efootball-apk\native\lib\arm64-v8a\libUE4.so")

gh = int(sys.argv[1], 16)
span = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x600

data = open(SO, "rb").read()
off = gh - 0x100000
chunk = data[off - span: off + span]
base = gh - span
for m in re.finditer(rb"[\x20-\x7e]{3,}", chunk):
    s = m.group().decode("ascii", "replace")
    mark = " <== ANCHOR" if base + m.start() == gh else ""
    print("%08x  %r%s" % (base + m.start(), s, mark))
