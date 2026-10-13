#!/usr/bin/env python3
"""sgr_types.py -- per-key value type from the SET_GAME_RESULT disassembly.

Reads sgr_enc.dis (dis_range.py output over the serializer at 0x76d45c8),
find every setkey site (bl 0x2f92514 with a key string loaded into x1) and
records which value-writer helper runs before the next setkey site.

Helpers (decoded from the encoder's call pattern setkey -> 0x2f8f898 ->
0x2f91730 -> VALUE -> next):

  0x2f9135c(tmp, w1)  INT      (w1 from an ldr/ldur word)
  0x2f913c8(tmp, x1)  STRING   (x1 = std::string cstr via SSO csel)
  0x2f91374(tmp, w1)  BOOL/enum (source word -> "YES"/"NO"-style)
  0x2f912cc(slot, 0)  new empty MAP
  0x2f9138c(dst, src) object/container assign (attach)
  0x74e22a0           vector element load (LIST loop)

Keys with NO writer before the next setkey are flagged -- their value is
written after a nested block (parent-attach pattern) and need manual eyes.
"""
import re
import sys

SETKEY = "bl       #0x2f92514"
STR_RE = re.compile(r"STR 0x[0-9a-f]+ '([^']+)'")
BL_RE = re.compile(r"bl       #(0x[0-9a-f]+)")

HELPERS = {
    "0x2f9135c": "INT",
    "0x2f913c8": "STRING",
    "0x2f91374": "BOOL",
    "0x2f912cc": "NEWMAP",
    "0x2f9138c": "ASSIGN",
    "0x74e22a0": "VECTEL",
}


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        r"C:\Users\Administrator\Documents\Default Project\work\sgr_enc.dis"
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()

    # pre-scan: pc -> key for each setkey (adrp-with-STR within 6 lines back)
    rows = []          # (pc, key, [helpers between here and next setkey])
    last_key = None
    for i, ln in enumerate(lines):
        if SETKEY in ln:
            key = None
            for j in range(i, max(-1, i - 8), -1):
                m = STR_RE.search(lines[j])
                if m:
                    key = m.group(1)
                    break
                m = BL_RE.search(lines[j])
                if m and j != i:
                    break
            pc = ln.split()[0]
            rows.append({"pc": pc, "key": key or last_key or "?", "helpers": []})
            last_key = rows[-1]["key"]

    # assign helpers: scan from each setkey to the next setkey
    for k, row in enumerate(rows):
        start = next(i for i, ln in enumerate(lines)
                     if ln.startswith(row["pc"]))
        end = len(lines)
        if k + 1 < len(rows):
            end = next(i for i, ln in enumerate(lines)
                       if ln.startswith(rows[k + 1]["pc"]))
        seen = []
        for ln in lines[start:end]:
            m = BL_RE.search(ln)
            if not m:
                continue
            h = HELPERS.get(m.group(1))
            if h and h not in seen:
                seen.append(h)
        row["helpers"] = seen

    for row in rows:
        mark = ",".join(row["helpers"]) or "*** NONE (value written later?)"
        print("%-34s %-10s %s" % (row["key"], row["pc"], mark))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
