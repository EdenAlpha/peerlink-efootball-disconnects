#!/usr/bin/env python3
"""sgr_keycheck.py -- diff our SET_GAME_RESULT body keys vs the binary's.

The 123-key body in chain3.sgr_request was hand-transcribed from the
11.1.0 serializer disassembly.  One mistyped key anywhere = GKZX-.
This extracts every key string the serializer actually emits
(%TEMP%\\sgr1110_full.dis, the 0x7795324..0x7796fb4 dump) and diffs it
against the key names our body uses, at every nesting level.

  python sgr_keycheck.py
"""
import os
import re
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import chain3 as c3                                # noqa: E402

DIS = os.path.join(os.environ.get("TEMP", "."), "sgr1110_full.dis")


def dis_keys(path):
    """key strings setkey'd into a root (STR lines in the serializer dump).

    The dump may be UTF-16 (PowerShell redirect) -- sniff the BOM.
    """
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    out = []
    for line in text.splitlines():
        m = re.search(r"; STR 0x[0-9a-f]+ '([^']*)'", line)
        if m:
            out.append(m.group(1))
    return out


def body_keys(v, out):
    if isinstance(v, dict):
        for k, x in v.items():
            out.add(k)
            body_keys(x, out)
    elif isinstance(v, list):
        for x in v:
            body_keys(x, out)


def main():
    req = c3.sgr_request(1, [], [], 2, 1, "NONE", 320)
    ours = set()
    body_keys(req, ours)
    theirs = dis_keys(DIS)
    tset = set(theirs)

    print("serializer keys: %d (%s)" % (len(theirs), DIS))
    print("our body keys  : %d" % len(ours))

    missing = sorted(ours - tset)
    print("\nin OUR body but NOT in the serializer dump (%d):" % len(missing))
    for k in missing:
        print("  %r" % k)

    emitted = sorted(tset - ours)
    print("\nemitted by serializer but absent from our body (%d): %s"
          % (len(emitted), emitted[:40]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
