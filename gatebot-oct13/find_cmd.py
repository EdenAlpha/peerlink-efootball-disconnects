#!/usr/bin/env python3
"""find_cmd.py -- locate a Cmd*.php string in libUE4.so and list code xrefs.

usage: python find_cmd.py <libUE4.so> <needle>

Prints every adrp/add xref site for the needle string.  The first xrefs are
the command ctors (they store the php name at this+0x170); the serializer /
request-builder function is usually the next function after the ctor.
"""
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher\scripts")
from xref2 import Elf, find_xrefs  # noqa: E402


def main():
    path, needle = sys.argv[1], sys.argv[2].encode()
    e = Elf(path)
    hits = []
    for t, fl, nm, addr, off, sz in e.sections:
        chunk = e.read(off, sz)
        i = chunk.find(needle)
        while i >= 0:
            hits.append(addr + i)
            i = chunk.find(needle, i + 1)
    if not hits:
        print("FAIL: %r not found" % needle.decode())
        return
    for va in hits:
        print("string va=0x%x" % va)
    refs = find_xrefs(path, hits)
    for va, pcs in refs.items():
        if not pcs:
            print("  0x%x: no adrp/add xref" % va)
        for pc in pcs:
            print("  0x%x <- code 0x%x" % (va, pc))


if __name__ == "__main__":
    main()
