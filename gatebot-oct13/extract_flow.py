#!/usr/bin/env python3
"""extract_flow.py -- pull the FULL decomp body of every post-room-flow
function out of the fulldump2 dumps into one file, then find every
OTHER function that CALLS them (the state machine that drives the flow).

Functions (old-binary Ghidra addrs, from flow_scan.py):
"""
import os
import re
import sys

D = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_sgr"
FILES = ["punch", "natwire", "rp_dispatch"]          # preferred order
MAIN = os.path.join(D, "fulldump2_out.txt")

WANT = [
    # session / start-game orchestrators
    "07e5bc34", "07e2cae8", "07723140", "07727030", "07727894",
    "077e15d4", "077e3d44",
    # TURN server list
    "07eaf040", "07eaf5c8", "07eaf14c", "07eaf768",
    # TURN address data (get / watch / send)
    "07ead160", "07ead330", "07ead464",
    "07eade70", "07eae040", "07eae174",
    "07eb11f0", "07eb1908", "07eb12f0",
    # relay quality
    "077e8b08", "077e98d4", "0772a380", "0772a550",
    "077e482c", "077e5204",
    # NAT / reflexive proof
    "078108fc", "078b1ba4", "078c5c5c", "078d3b50",
    # punch candidates + phases/score + result read
    "07724da0", "07e36874", "07721a70",
]


def blocks(path):
    """yield (addr, text) for each ==== block."""
    cur, buf = None, []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("==== "):
                if cur is not None:
                    yield cur, "".join(buf)
                cur = line.split()[1]
                buf = [line]
            elif cur is not None:
                buf.append(line)
    if cur is not None:
        yield cur, "".join(buf)


found = {}
for tag in FILES:
    path = os.path.join(D, tag, "fulldump2_out.txt")
    sys.stderr.write("extract %s ...\n" % tag)
    for addr, text in blocks(path):
        if addr in WANT and addr not in found:
            found[addr] = (tag, text)
    if len(found) == len(WANT):
        break
# anything still missing -> main dump
miss = [a for a in WANT if a not in found]
if miss:
    sys.stderr.write("main dump for %d missing\n" % len(miss))
    for addr, text in blocks(MAIN):
        if addr in miss:
            found[addr] = ("main", text)
            miss.remove(addr)
            if not miss:
                break

out = []
for a in WANT:
    if a in found:
        tag, text = found[a]
        out.append("\n########## from=%s ##########\n" % tag)
        out.append(text)
    else:
        out.append("\n########## %s NOT FOUND ##########\n" % a)
dst = os.path.join(D, "..", "flow_decomp.txt")
open(dst, "w", encoding="utf-8").write("".join(out))
print("extracted %d/%d -> %s (%.1f MB)"
      % (len(found), len(WANT), dst, os.path.getsize(dst) / 1e6))
print("missing: %s" % ([a for a in WANT if a not in found] or "none"))

# ---- callers: who references these FUN_ names elsewhere in the dumps ----
call_re = re.compile(rb"FUN_(%s)\s*\(" % b"|".join(w.encode() for w in WANT))
caller_hits = {}
for tag in FILES + ["main"]:
    path = (os.path.join(D, tag, "fulldump2_out.txt") if tag != "main"
            else MAIN)
    cur = None
    with open(path, "rb") as f:
        for line in f:
            if line.startswith(b"==== "):
                cur = line.split()[1].decode()
            elif cur is not None:
                for m in call_re.finditer(line):
                    tgt = m.group(1).decode()
                    if cur != "FUN_" + tgt and cur != tgt:
                        caller_hits.setdefault(tgt, set()).add(
                            (tag, cur))
cs = []
for tgt in sorted(caller_hits):
    cs.append("== called by %s:" % tgt)
    for tag, fn in sorted(caller_hits[tgt]):
        cs.append("   %s [%s]" % (fn, tag))
cdst = os.path.join(D, "..", "flow_callers.txt")
open(cdst, "w", encoding="utf-8").write("\n".join(cs))
print("callers -> %s (%d lines)" % (cdst, len(cs)))
