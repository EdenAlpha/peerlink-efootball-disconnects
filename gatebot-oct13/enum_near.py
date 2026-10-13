#!/usr/bin/env python3
"""enum_near.py -- dump rodata strings near a marker (enum-table hunt).

UE4 lays string literals out contiguously, so sibling enum values of a
field sit next to each other.  Find DISCONN_HB / NORMAL / GKZX- and
print the neighborhood: that is the field's legal vocabulary.

  python enum_near.py DISCONN_HB
"""
import re
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")


def main() -> int:
    needle = sys.argv[1] if len(sys.argv) > 1 else "DISCONN_HB"
    data = open(SO, "rb").read()
    strs = [(m.start(), m.group().decode())
            for m in re.finditer(rb"[ -~]{3,24}", data)]
    idx = [i for i, (_, s) in enumerate(strs) if s == needle]
    print("%s hits: %d" % (needle, len(idx)))
    for i in idx[:3]:
        print("\n== around 0x%x ==" % strs[i][0])
        for j in range(max(0, i - 16), min(len(strs), i + 17)):
            off, s = strs[j]
            mark = ">>" if j == i else "  "
            print("%s 0x%08x %s" % (mark, off, s))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
