#!/usr/bin/env python3
"""sgr_typecheck.py -- diff our SET_GAME_RESULT value TYPES vs the binary.

Key names are verified exact (sgr_keycheck).  A single msgpack type
mismatch (int sent where the serializer writes string, etc.) is a
GKZX- the same as a wrong value.  The serializer writes each value via
a helper immediately before setkey'ing its key:

    0x2fcb670 = int32     bl #0x2fcb670
    0x2fcb6dc = string    bl #0x2fcb6dc   (SSO: tst w8,#1 / csel)
    0x2fcc828 = setkey    (map, key) -- the KEY str follows a bl to it
    loop markers          ldp x19,x8 / cmp / b.eq  = list vectors

For each STR 'key' line, look back for the most recent value-writer
call and classify: INT / STR / LIST (loop) / MAP.

  python sgr_typecheck.py
"""
import os
import re
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import chain3 as c3                                # noqa: E402

DIS = os.path.join(os.environ.get("TEMP", "."), "sgr1110_full.dis")

WRITERS = {
    "0x2fcb670": "INT",
    "0x2fcb6dc": "STR",
    "0x2fcb6a0": "NUM",   # likely int64/double
    "0x2fcb640": "NUM",
    "0x2fcb640": "NUM",
}


def classify(lines, idx):
    """walk back from a setkey'd key line; classify the value writer"""
    saw_loop = False
    for j in range(idx - 1, max(0, idx - 40), -1):
        m = re.search(r"bl\s+#(0x[0-9a-f]+)", lines[j])
        if m:
            t = WRITERS.get(m.group(1))
            if t:
                return ("LIST:" + t) if saw_loop else t
        if re.search(r"b\.eq\s+#0x[0-9a-f]+", lines[j]):
            saw_loop = True
    return "MAP/LIST?"


def main():
    raw = open(DIS, "rb").read()
    text = raw.decode("utf-16", errors="replace") \
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff") \
        else raw.decode("utf-8", errors="replace")
    lines = text.splitlines()

    keytype = {}
    for i, ln in enumerate(lines):
        m = re.search(r"; STR 0x[0-9a-f]+ '([^']*)'", ln)
        if m and i + 3 < len(lines) \
                and any("0x2fcc828" in lines[k] for k in range(i, i + 4)):
            keytype[m.group(1)] = classify(lines, i)

    # our body: walk with types
    req = c3.sgr_request(1, [{}], [{}], 2, 1, "NONE", 320)

    def ours(v, out, path=""):
        if isinstance(v, dict):
            for k, x in v.items():
                ours(x, out, path + "." + k)
        elif isinstance(v, list):
            out[path] = "LIST:list" if v else "EMPTY"
        elif isinstance(v, bool):
            out[path] = "bool"
        elif isinstance(v, int):
            out[path] = "INT"
        elif isinstance(v, float):
            out[path] = "NUM"
        elif isinstance(v, str):
            out[path] = "STR"
        else:
            out[path] = type(v).__name__

    got = {}
    ours(req, got)

    print("serializer key->writer types: %d keys" % len(keytype))
    print("\nMISMATCHES (top-level and one nest deep):")
    n = 0
    for path, t in sorted(got.items()):
        leaf = path.rsplit(".", 1)[-1]
        st = keytype.get(leaf)
        if st is None:
            continue
        if st.startswith("LIST") and t.startswith("LIST"):
            continue
        if st == "MAP/LIST?" and t == "MAP":
            continue
        if st != t and not (st == "NUM" and t == "NUM"):
            print("  %-42s ours=%-10s serializer=%s" % (path, t, st))
            n += 1
    print("(%d mismatches)" % n)

    print("\nour types for the guard-adjacent keys:")
    for k in ("match_result.error_code", "match_result.is_problem",
              "match_result.event_record", "match_result.control_style",
              "match_result.restart_num", "match_result.ex_flag",
              "match_result.pk_flag", "match_result.use_team_style",
              "match_result.use_setting_multi_formation"):
        print("  %-45s %s" % (k, got.get(k, "(absent)")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
