#!/usr/bin/env python3
"""verify_secrets.py -- strict check: flag only literal-looking credential
values left in a tree (quoted strings, bare token blobs, long numbers).

  python verify_secrets.py <root>
"""
import os
import re
import sys

KEYS = ("user_id", "session_id", "auth_code", "auth_key", "auth_token",
        "account_id", "user_name", "password", "s_keyword", "sign", "token")

OK = re.compile(r"^(<redacted>|null|true|false|none|notimplement|0|1|-1|"
                r"[a-z_][a-z0-9_.]*(\(|$)|\)|\]|,|\"|')$", re.I)

# value = quoted string (>=6) | bare blob (>=12 with a digit) | big number
VAL = re.compile(
    r'(?<![A-Za-z0-9_<])("?(?:' + "|".join(KEYS) + r')"?\s*[:=]\s*)'
    r'("[^"]{6,}"|\'[^\']{6,}\'|[A-Za-z0-9+/=_-]{12,}|\d{6,})')

PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def walk(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d != "__pycache__"]
        for fn in fns:
            yield os.path.join(dp, fn)


def main(root):
    hits = []
    for path in walk(root):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for rx, label in ((PEM, "PEM"), (VAL, "LITERAL")):
            for m in rx.finditer(text):
                s = m.group(0)
                v = m.group(m.lastindex) if m.lastindex else s
                if OK.match(str(v).strip()):
                    continue
                if str(v).lower().startswith("<redacted"):
                    continue
                hits.append("%s %s :: %s" % (label, os.path.relpath(path, root),
                                            s[:100]))
    if hits:
        print("SUSPICIOUS (%d):" % len(hits))
        for h in hits[:60]:
            print(" ", h)
        return 1
    print("CLEAN: no literal credential values")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
