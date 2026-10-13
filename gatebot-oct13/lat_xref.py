import sys, struct
from xref2 import Elf, find_xrefs

PATH = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native1110\libUE4.so"
elf = Elf(PATH)

def off_to_va(off):
    for t, fl, nm, addr, foff, sz in elf.sections:
        if foff <= off < foff + sz:
            return addr + (off - foff), nm
    return None, None

names = ["LATENCY_MODE_MATCHING", "LATENCY_MODE_SESSION", "LATENCY_MODE_CONNECT",
         "LATENCY_MODE_ANNTENA", "LATENCY_MODE_PRE_MENU",
         "LATENCY_MODE_MATCH_SETTEING_INIT", "LATENCY_MODE_WHOLE_CONNECTING",
         "LATENCY_MODE_CONFIRMING_RESULT"]
want = []
loc = {}
for nm in names:
    off = elf.data.find(nm.encode() + b"\x00")
    if off < 0:
        print(nm, "NOT FOUND"); continue
    va, sec = off_to_va(off)
    print("=== %-35s off=0x%x va=0x%x (%s)" % (nm, off, va, sec))
    loc[nm] = va
    want.append(va)

xrefs = find_xrefs(PATH, want)
v2n = {v: n for n, v in loc.items()}
for va in want:
    pcs = xrefs.get(va, [])
    print("%-35s va=0x%x  %d xrefs" % (v2n[va], va, len(pcs)))
    for pc in pcs:
        print("    pc=0x%x (vaddr)" % pc)
