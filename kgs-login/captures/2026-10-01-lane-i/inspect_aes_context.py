#!/usr/bin/env python3
"""Examine the context around every AES256 hit in the live libUE4.so rw segment.

The 42 MB read-write mapping was dumped from the running game. Eight occurrences
of the literal "AES256" were found in it. This prints the neighbourhood of each,
so the cipher configuration can be read directly instead of guessed at.

What to look for:
  * the header name the game writes ("pes-custom-encrypt") -- if it sits near
    one of these, that is the request-encryption path
  * 16/24/32-byte printable runs -- AES-128/192/256 key lengths
  * other literals that name the scheme ("CBC", "GCM", "NoPadding")
"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "libUE4_rw.so"
blob = open(path, "rb").read()
print("file: %s  %d bytes (%.1f MB)" % (path, len(blob), len(blob) / 1048576.0))

PRINTABLE = set(range(0x20, 0x7F))


def runs(data, lo, hi, minlen=4):
    """Printable runs intersecting [lo, hi), with their absolute offsets."""
    out = []
    cur, start = [], None
    for i in range(lo, hi):
        b = data[i]
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


hits = [m.start() for m in re.finditer(b"AES256", blob)]
print("AES256 hits: %d -> %s" % (len(hits), hits))
print()

for n, off in enumerate(hits, 1):
    lo = max(0, off - 512)
    hi = min(len(blob), off + 512)
    print("=" * 72)
    print("[%d] AES256 at 0x%x (%d)" % (n, off, off))
    for so, s in runs(blob, lo, hi):
        mark = ""
        if so <= off < so + len(s):
            mark = "  <== contains the hit"
        if len(s) in (16, 24, 32):
            mark += "  <== KEY-LENGTH RUN (%d)" % len(s)
        print("   0x%08x  %r%s" % (so, s, mark))

print()
print("=" * 72)
print("Key-length candidate runs (16/24/32 printable chars) in the whole segment:")
for m in re.finditer(rb"(?<![ -~])[ -~]{16}(?![ -~])|(?<![ -~])[ -~]{24}(?![ -~])|(?<![ -~])[ -~]{32}(?![ -~])", blob):
    s = m.group()
    if not re.search(rb"[A-Za-z]", s):
        continue
    print("   0x%08x len=%-3d %r" % (m.start(), len(s), s))