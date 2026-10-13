#!/usr/bin/env python3
"""sgr_diff.py -- ordered key-list diff of two SET_GAME_RESULT serializer dumps.

usage: python sgr_diff.py <11.0.1.dis> <11.1.0.dis>

Both inputs are dis_range.py output.  Every `adrp ... ; STR addr 'key'`
annotation is one emitted key; the ordered sequences are compared with
difflib so repeated keys (id/serial/...) stay positional.
"""
import difflib
import re
import sys

STR = re.compile(r"(0x[0-9a-f]+)\s+adrp.*; STR 0x[0-9a-f]+\s+'([^']+)'")


def open_any(path):
    # PowerShell '>' writes UTF-16 with BOM; detect it.
    with open(path, "rb") as f:
        magic = f.read(2)
    enc = "utf-16" if magic in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
    return open(path, encoding=enc, errors="replace")


def keys(path):
    out = []
    for line in open_any(path):
        m = STR.search(line)
        if m:
            out.append((int(m.group(1), 16), m.group(2)))
    return out


def main():
    a, b = keys(sys.argv[1]), keys(sys.argv[2])
    ka = [k for _, k in a]
    kb = [k for _, k in b]
    print("A %s: %d keys (0x%x..0x%x)"
          % (sys.argv[1], len(ka), a[0][0], a[-1][0]) if a else "A empty")
    print("B %s: %d keys (0x%x..0x%x)"
          % (sys.argv[2], len(kb), b[0][0], b[-1][0]) if b else "B empty")
    sm = difflib.SequenceMatcher(None, ka, kb, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        print("%-7s A[%d:%d] %s | B[%d:%d] %s"
              % (tag, i1, i2, ka[i1:i2], j1, j2, kb[j1:j2]))
    print("ratio=%.4f" % sm.ratio())
    if ka == kb:
        print("IDENTICAL ordered key list")


if __name__ == "__main__":
    main()
