#!/usr/bin/env python3
"""Mine the traffic-time full dump (local 4.4GB) for login values and the key.

Phase 1 (fast): map every anchor to its region via index.txt.
Phase 2 (medium): 1MB windows around sign= hits -> session structs, URLs,
    request objects; save interesting windows to out/.
Phase 3 (slow): AES-256 schedule scan over heap regions only.

Usage: mine.py <dir-with-full.bin-and-index.txt> <outdir> [phase]
"""
import os
import re
import subprocess
import sys

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
SBOX = bytes((
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16))


def expand32_first64(key):
    w = [key[i:i + 4] for i in range(0, 32, 4)]
    out = bytearray(key)
    for i in range(8, 16):
        t = w[i - 1]
        if i % 8 == 0:
            t = bytes([SBOX[(t[(j + 1) % 4])] ^ (RCON[i // 8 - 1] if j == 0 else 0)
                       for j in range(4)])
        elif i % 8 == 4:
            t = bytes([SBOX[b] for b in t])
        wi = bytes([w[i - 8][j] ^ t[j] for j in range(4)])
        w.append(wi)
        out += wi
    return bytes(out)


def load_index(path):
    regs = []
    for line in open(path, errors="replace"):
        p = line.split()
        if len(p) < 5:
            continue
        try:
            off = int(p[3])
        except ValueError:
            continue
        if off < 0:
            # index.txt out_off was computed on-device with 32-bit arithmetic
            # and wrapped past 2GB. full.bin is <8GB so one wrap is exact.
            off += 1 << 32
        rng = p[0]
        if "-" not in rng:
            continue
        s, e = rng.split("-")
        try:
            regs.append((off, int(s, 16), int(e, 16), p[1], p[2][:70]))
        except ValueError:
            continue
    regs.sort()
    return regs


def region_of(regs, pos):
    lo, hi = 0, len(regs) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        if regs[m][0] <= pos:
            if m + 1 >= len(regs) or regs[m + 1][0] > pos:
                return regs[m]
            lo = m + 1
        else:
            hi = m - 1
    return None


def main():
    d = sys.argv[1]
    outd = sys.argv[2]
    phase = sys.argv[3] if len(sys.argv) > 3 else "12"
    os.makedirs(outd, exist_ok=True)
    full = os.path.join(d, "full.bin")
    regs = load_index(os.path.join(d, "index.txt"))
    print("regions: %d  size: %d" % (len(regs), os.path.getsize(full)))

    anchors = ["sign=", "gate_CMD_", "CMD_LOGIN", "session_id",
               "pes-custom-encrypt", "s_keyword", "msgid", "my_platform",
               "CMD_CREATE", "CMD_JOIN", "room", "Room"]
    import mmap
    hits = {}
    with open(full, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        for an in anchors:
            pat = an.encode()
            offs = [m.start() for m in re.finditer(re.escape(pat), mm)]
            hits[an] = offs
            print("%-20s n=%d" % (an, len(offs)))
            for o in offs[:8]:
                rg = region_of(regs, o)
                print("   %d -> %s" % (o, ("%x-%x %s %s" % (rg[1], rg[2], rg[3], rg[4])) if rg else "?"))
        mm.close()
    open(os.path.join(outd, "anchor_offsets.txt"), "w").write(
        "\n".join("%s %d" % (a, o) for a in hits for o in hits[a]))

    if "2" in phase:
        f = open(full, "rb")
        for an in ("sign=", "session_id"):
            for i, o in enumerate(hits.get(an, [])[:12]):
                f.seek(max(0, o - 4096))
                blob = f.read(8192)
                open(os.path.join(outd, "win_%s_%d.bin" % (an.replace("=", ""), i)), "wb").write(blob)
        print("windows saved")

    if "3" in phase:
        heap = [(off, s, e) for (off, s, e, p, n) in regs
                if ("anon" in n or "heap" in n or "scudo" in n or "dalvik" in n or "stack" in n)
                and (e - s) >= (1 << 20)]
        print("heap regions >=1MB: %d" % len(heap))
        f = open(full, "rb")
        n_c = n_s = checked = 0
        for (off, s, e) in heap:
            try:
                f.seek(off)
            except OSError as ex:
                print("SEEK FAIL off=%r s=%x e=%x: %s" % (off, s, e, ex))
                continue
            size = (e - s)
            # stream in 16MB pieces
            got = 0
            while got < size:
                blk = f.read(min(1 << 24, size - got))
                if not blk:
                    break
                for o in range(0, len(blk) - 64, 16):
                    w = blk[o:o + 32]
                    if all(32 <= x < 127 for x in w):
                        continue
                    if len(set(w)) < 26:
                        continue
                    n_c += 1
                    if blk[o + 32:o + 64] == expand32_first64(w)[32:64]:
                        n_s += 1
                        goff = off + got + o
                        print("SCHED MATCH @ %d (0x%x): %s" % (goff, goff, w.hex()))
                        open(os.path.join(outd, "key_cand_%d.bin" % goff), "wb").write(
                            blk[max(0, o - 512):o + 1024])
                got += len(blk)
                checked += len(blk)
                if checked % (1 << 28) == 0:
                    print("  ... %d MB, cands=%d sched=%d" % (checked >> 20, n_c, n_s))
        print("DONE cands=%d sched=%d" % (n_c, n_s))


if __name__ == "__main__":
    main()