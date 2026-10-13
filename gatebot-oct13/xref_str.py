#!/usr/bin/env python3
"""xref_str.py -- adrp/add code xrefs to given string vaddrs (both base guesses)."""
import sys
from xref2 import find_xrefs

SO = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
      r"\efootball-apk\native1110\libUE4.so")

addrs = [int(a, 16) for a in sys.argv[1:]]
vas = []
for a in addrs:
    vas += [a, a - 0x100000]
x = find_xrefs(SO, vas)
for v in vas:
    print(hex(v), [hex(p) for p in x.get(v, [])])
