"""fd.py - index + query the full Ghidra dump (fulldump_out.txt, ~2.6 GB).

The dump (from Actions run 37111881935, artifact kgs-ghidra) has sections:
PROGRAM BLOCKS SYMBOLS FUNCTIONS DATA STRINGS REFS ASM DECOMP SUMMARY.

Records:
  FUNC <addr> name=... size=... sig=...        (FUNCTIONS section)
  STR  <addr> <text> |<from>@<func> ...        (STRINGS section, with xrefs)
  ==== <addr> <name>  <decompiled C ...>       (DECOMP section)

Commands:
  python fd.py index                 build fd_sections.json / fd_decomp.txt / fd_func.txt
  python fd.py info                  sections + DECOMP coverage
  python fd.py decomp <hexaddr>      decompiled C of the function containing addr
  python fd.py grep <section> <re> [limit]     regex search within one section
"""
import json
import os
import re
import sys
import bisect

BASE = os.path.dirname(os.path.abspath(__file__))
DUMP = os.path.join(os.path.dirname(BASE), "work", "ghidra_artifact", "fulldump_out.txt")
if not os.path.exists(DUMP):
    DUMP = r"C:\Users\Administrator\Documents\Default Project\work\ghidra_artifact\fulldump_out.txt"
SECJ = os.path.join(os.path.dirname(DUMP), "fd_sections.json")
DIDX = os.path.join(os.path.dirname(DUMP), "fd_decomp.txt")
FIDX = os.path.join(os.path.dirname(DUMP), "fd_func.txt")


def index():
    sections = {}
    dcount = 0
    fcount = 0
    first_d = last_d = None
    in_decomp = False
    in_func = False
    off = 0
    with open(DUMP, "rb") as f, open(DIDX, "w") as df, open(FIDX, "w") as ff:
        for line in f:
            if line.startswith(b"========== "):
                name = line.decode("ascii", "replace").strip().strip("=").strip()
                sections[name] = off
                in_decomp = name == "DECOMP"
                in_func = name == "FUNCTIONS"
            elif in_decomp and line.startswith(b"==== "):
                try:
                    addr = int(line.split()[1], 16)
                except Exception:
                    addr = -1
                df.write("%d %d\n" % (addr, off))
                if first_d is None:
                    first_d = addr
                last_d = addr
                dcount += 1
            elif in_func and line.startswith(b"FUNC "):
                try:
                    addr = int(line.split()[1], 16)
                except Exception:
                    addr = -1
                ff.write("%d %d\n" % (addr, off))
                fcount += 1
            off += len(line)
    meta = {"size": off, "sections": sections, "decomp": dcount,
            "decomp_first": first_d, "decomp_last": last_d, "func": fcount}
    with open(SECJ, "w") as j:
        json.dump(meta, j, indent=1)
    print(json.dumps(meta, indent=1))


def load_sections():
    with open(SECJ) as j:
        return json.load(j)


def load_idx(path):
    addrs, offs = [], []
    with open(path) as fh:
        for ln in fh:
            a, o = ln.split()
            addrs.append(int(a))
            offs.append(int(o))
    return addrs, offs


def section_bounds(meta, name):
    secs = meta["sections"]
    starts = sorted((v, k) for k, v in secs.items())
    for i, (v, k) in enumerate(starts):
        if k == name:
            end = starts[i + 1][0] if i + 1 < len(starts) else meta["size"]
            return v, end
    raise SystemExit("no section %s (have: %s)" % (name, ",".join(secs)))


def cmd_info():
    meta = load_sections()
    print(json.dumps(meta, indent=1))
    for name in ("FUNCTIONS", "STRINGS", "DECOMP"):
        a, b = section_bounds(meta, name)
        print("%-10s %12d .. %12d  (%.1f MB)" % (name, a, b, (b - a) / 1048576.0))


def cmd_decomp(addr_s):
    addr = int(addr_s, 16)
    addrs, offs = load_idx(DIDX)
    i = bisect.bisect_right(addrs, addr) - 1
    if i < 0:
        raise SystemExit("addr below first decompiled function %08x" % addrs[0])
    start = offs[i]
    end = offs[i + 1] if i + 1 < len(offs) else os.path.getsize(DUMP)
    with open(DUMP, "rb") as f:
        f.seek(start)
        # a function's C is at most 120k chars + header; clamp reads anyway
        chunk = f.read(min(end - start, 300000))
    text = chunk.decode("utf-8", "replace")
    sys.stdout.write(text)


def cmd_grep(sec, pattern, limit=50):
    meta = load_sections()
    a, b = section_bounds(meta, sec)
    rx = re.compile(pattern.encode("utf-8"))
    n = 0
    with open(DUMP, "rb") as f:
        f.seek(a)
        remaining = b - a
        while remaining > 0:
            line = f.readline()
            if not line:
                break
            remaining -= len(line)
            if rx.search(line):
                sys.stdout.write(line.decode("utf-8", "replace"))
                n += 1
                if n >= limit:
                    print("... (limit %d)" % limit)
                    return


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    c = sys.argv[1]
    if c == "index":
        index()
    elif c == "info":
        cmd_info()
    elif c == "decomp":
        cmd_decomp(sys.argv[2])
    elif c == "grep":
        lim = int(sys.argv[4]) if len(sys.argv) > 4 else 50
        cmd_grep(sys.argv[2], sys.argv[3], lim)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
