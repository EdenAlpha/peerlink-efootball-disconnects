#!/usr/bin/env python3
"""Read the game's own encryption configuration out of the live .rodata dump.

The device-side greps proved unreliable (they reported zero hits for literals
that are demonstrably present), so all of this is done offline against the
pulled segment. The header literal "pes-custom-encrypt" is at 0xad120e, which is
game-specific code, unlike the OpenSSL cipher-suite strings at 0x9c7xxx.
"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "libUE4_rw.so"
blob = open(path, "rb").read()

PRINTABLE = set(range(0x20, 0x7F))


def runs(lo, hi, minlen=4):
    out, cur, start = [], [], None
    for i in range(lo, hi):
        b = blob[i]
        if b in PRINTABLE:
            if not cur:
                start = i
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                out.append((start, "".join(cur)))
            cur, start = [], None
    if len(cur) >= minlen:
        out.append((start, "".join(cur)))
    return out


ANCHOR = blob.find(b"pes-custom-encrypt")
print("segment %d bytes, pes-custom-encrypt at 0x%x" % (len(blob), ANCHOR))
print()

# The game's own string neighbourhood. OpenSSL lives around 0x9c0000; the game's
# literals start near 0xa9xxxx. Compare the two so library noise is obvious.
for label, centre in (("pes-custom-encrypt", ANCHOR),
                      ("s_keyword", blob.find(b"s_keyword")),
                      ("first AES256 (OpenSSL)", blob.find(b"AES256"))):
    lo = max(0, centre - 700)
    hi = min(len(blob), centre + 700)
    print("=" * 74)
    print("%s @ 0x%x" % (label, centre))
    print("-" * 74)
    for so, s in runs(lo, hi):
        tag = ""
        if len(s) in (16, 24, 32):
            tag = "   [len %d]" % len(s)
        print("  0x%08x  %r%s" % (so, s, tag))
    print()