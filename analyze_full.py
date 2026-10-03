#!/usr/bin/env python3
"""Scan the full memory dump for login-relevant anchors.

full.bin is ~4GB; use grep (fast, 64-bit) for byte offsets, then map each hit
back to its source region via index.txt (range, perms, name, out_offset).
"""
import os
import subprocess
import sys

FULL = "/tmp/kgs/full/full.bin"
INDEX = "/tmp/kgs/full/index.txt"

ANCHORS = ["sign=", "gate_CMD_", "CMD_LOGIN", "session_id",
           "pes-custom-encrypt", "s_keyword"]
# A captured sign= cookie value is a live session token. Supply it via the
# environment (SIGN_B64) rather than committing it; the repo is public.
if os.environ.get("SIGN_B64"):
    ANCHORS.append(os.environ["SIGN_B64"])


def load_index():
    regs = []
    for line in open(INDEX, errors="replace"):
        p = line.split()
        if len(p) < 5:
            continue
        rng, perms, name, off = p[0], p[1], p[2], int(p[3])
        s, e = rng.split("-")
        regs.append((off, int(s, 16), int(e, 16), perms, name))
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
    regs = load_index()
    print("index regions: %d" % len(regs))
    for an in ANCHORS:
        try:
            out = subprocess.run(["grep", "-abo", "-m", "12", "-F", an, FULL],
                                 capture_output=True, text=True, timeout=300)
        except Exception as e:
            print("%-18s ERROR %s" % (an, e))
            continue
        lines = [l for l in out.stdout.splitlines() if ":" in l]
        print("%-18s hits=%d" % (an, len(lines)))
        for l in lines[:12]:
            pos = int(l.split(":")[0])
            r = region_of(regs, pos)
            if r:
                print("   fileoff=%d -> %x-%x %s %s" % (pos, r[1], r[2], r[3], r[4][:60]))


main()