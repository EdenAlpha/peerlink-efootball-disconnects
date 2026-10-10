#!/usr/bin/env python3
"""Extract libUE4.so from the full memory dump."""
import os

D = r"C:\Users\Administrator\AppData\Local\Temp\2\artj\kgs-gappslive-36963768970\kgs\full"
MAPS = D + r"\maps.txt"
INDEX = D + r"\index.txt"
FULL = D + r"\full.bin"
OUT = D + r"\libUE4.so"

# maps: libUE4.so segments -> (file_off_within_so, vaddr_start, vaddr_end, perms)
segs = []
for line in open(MAPS, errors="replace"):
    if "/lib/arm64/libUE4.so" not in line:
        continue
    p = line.split()
    fo = int(p[2], 16)
    s, e = p[0].split("-")
    segs.append((fo, int(s, 16), int(e, 16), p[1]))
segs.sort()
print("maps segments:")
for fo, s, e, pm in segs:
    print("  file_off 0x%x  va 0x%x-0x%x  %s  size 0x%x" % (fo, s, e, pm, e - s))

# index: vaddr_start -> dump file offset.
# The index's path column is truncated, so join on the vaddr range exactly.
idx = {}
for line in open(INDEX, errors="replace"):
    p = line.split()
    if len(p) < 3:
        continue
    try:
        vaddr_start = int(p[0].split("-")[0], 16)
    except (ValueError, IndexError):
        continue
    # format: vaddr-vaddr perms fileoff_dev_inode_path dumpoff size
    try:
        dump_off = int(p[-2])
    except (ValueError, IndexError):
        continue
    if dump_off < 0:
        dump_off += 1 << 32
    idx[vaddr_start] = dump_off
print("index regions parsed: %d" % len(idx))
for s in sorted(set(s for _, s, _, _ in segs)):
    print("  seg start 0x%x -> dump_off 0x%x" % (s, idx.get(s, -1)))

out = open(OUT, "wb")
for fo, s, e, pm in segs:
    size = e - s
    if s in idx:
        doff = idx[s]
        out.seek(fo)
        with open(FULL, "rb") as f:
            f.seek(doff)
            out.write(f.read(size))
        print("extracted file_off 0x%x  size %d  from dump 0x%x"
              % (fo, size, doff))
    else:
        print("  MISSED vaddr 0x%x" % s)
out.close()
print("\nwrote %s  size %d" % (OUT, os.path.getsize(OUT)))
