# sgr_join.py -- join serializer field-offset loads (sgr_enc.dis) with the
# ctor defaults (FUN_077d4270 decomp) -> offset -> (key, default) table.
# The serializer loads a field from [xN, #off] then attaches it under a STR-
# annotated setkey within a few instructions; the ctor writes defaults at
# the same byte offsets (SSO strings: len byte at off, data at off+1).
import re, sys

DIS = r"C:\Users\Administrator\Documents\Default Project\work\sgr_enc.dis"
CTOR = (r"C:\Users\Administrator\Documents\Default Project\work"
        r"\ghidra_sgr\fulldump2_out.txt")

# ---- 1. serializer: collect (offset, key) with register + line order ------
ldr = re.compile(r"^0x([0-9a-f]+)\s+ldr\w*\s+\w+,\s*\[(x\d+),\s*#0x([0-9a-f]+)\]")
strkey = re.compile(r";\s*STR\s+0x[0-9a-f]+\s+'([^']+)'")
lines = open(DIS, encoding="utf-8", errors="replace").read().splitlines()
pairs = []  # (line_no, reg, offset, key)
recent = {}  # reg -> (line_no, offset)
for i, ln in enumerate(lines):
    m = ldr.match(ln)
    if m:
        recent[m.group(2)] = (i, int(m.group(3), 16))
        continue
    m = strkey.search(ln)
    if m:
        # nearest load on any register within the last 8 lines
        best = None
        for reg, (li, off) in recent.items():
            if 0 <= i - li <= 8:
                if best is None or li > best[1]:
                    best = (off, li, reg)
        if best:
            pairs.append((i, best[2], best[0], m.group(1)))

# ---- 2. ctor: byte-offset -> default literal --------------------------------
txt = open(CTOR, encoding="utf-8", errors="replace").read()
seg = txt[txt.index("==== 077d4270"):]
seg = seg[:seg.index("==== 077d455c")]
# SSO wide strings: strncpy at (off) gives data at off; len byte at off-1.
# "NotImplement": 12 chars.  "NOERR": 5.  "NO": 2.
defaults = {}
for m in re.finditer(r'builtin_strncpy\(\(char \*\)\(\(long\)param_1 \+ 0x([0-9a-f]+)\),"([^"]+)"', seg):
    off, s = int(m.group(1), 16), m.group(2)
    defaults[off] = s  # data offset (len byte = off-1)
for m in re.finditer(r'\*\(undefined4 \*\)\(\(long\)param_1 \+ 0x([0-9a-f]+)\) = 0x([0-9a-f]+);', seg):
    off, v = int(m.group(1), 16), m.group(2)
    try:
        b = bytes.fromhex(v)[::-1].decode("ascii")
        if b.isprintable():
            defaults.setdefault(off, b)
    except Exception:
        pass
for m in re.finditer(r'\*\(undefined2 \*\)\(\(long\)param_1 \+ 0x([0-9a-f]+)\) = 0x([0-9a-f]+);', seg):
    off, v = int(m.group(1), 16), m.group(2)
    try:
        b = bytes.fromhex(v)[::-1].decode("ascii")
        if b.isprintable():
            defaults.setdefault(off, b)
    except Exception:
        pass

# ---- 3. join ---------------------------------------------------------------
print("%-4s %-6s %-9s %-42s %s" % ("line", "reg", "offset", "key", "ctor-default"))
for (i, reg, off, key) in pairs:
    d = defaults.get(off, defaults.get(off + 1, ""))
    print("%-4d %-6s 0x%-6x %-42s %s" % (i + 1, reg, off, key, d))
