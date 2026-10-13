#!/usr/bin/env python3
"""redact_batch.py -- redact every text file in a staging tree in place.

Applies work/redact.py's exact patterns (imported by path), then verifies
no credential VALUE remains. Binary-ish files (NUL in first bytes) are
skipped. Prints per-file redaction counts + any leftovers.
"""
import importlib.util
import os
import re
import sys

RED = r"C:\Users\Administrator\Documents\Default Project\work\redact.py"
spec = importlib.util.spec_from_file_location("redact", RED)
red = importlib.util.module_from_spec(spec)
spec.loader.exec_module(red)

TEXT_EXT = {".py", ".md", ".json", ".txt", ".log", ".csv", ".html",
            ".yml", ".yaml", ".cfg", ".dis", ".java", ".sh", ".c", ".h",
            ".gitignore", ".gitattributes", ".toml", ".ini"}

# leftover detectors: value after sensitive key must be <redacted>
LEFT = re.compile(
    r'(?<![A-Za-z0-9_<])("?(?:user_id|session_id|auth_code|auth_key|'
    r'auth_token|account_id|user_name|password|s_keyword|sign)"?\s*[:=]\s*)'
    r'(?!<redacted>|null|true|false|-?\d+\s*[,}\n]?|"?\s*[,}\]\n]|NotImplement)',
    re.I)
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
TOKEN = re.compile(r'\b(?:auth_code|auth_token|session_id|sign|token)='
                   r'(?!<redacted>)[A-Za-z0-9+/=_-]{16,}')


def is_text(path):
    if os.path.splitext(path)[1].lower() not in TEXT_EXT \
            and os.path.basename(path) not in (".gitignore", ".gitattributes"):
        return False
    with open(path, "rb") as fh:
        head = fh.read(2048)
    return b"\x00" not in head


def main(root):
    nred = nskip = nfile = 0
    problems = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if not is_text(path):
                nskip += 1
                continue
            raw = open(path, "rb").read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", errors="replace")
            out = []
            count = 0
            for line in text.splitlines(keepends=True):
                l2 = red.PAT.sub(red.sub, line)
                l2 = red.PAT2.sub(lambda m: m.group(1) + "=<redacted>", l2)
                if l2 != line:
                    count += line.count("\n") or 1
                out.append(l2)
            new = "".join(out)
            if count:
                open(path, "w", encoding="utf-8", newline="").write(new)
                nred += count
            nfile += 1
            for rx, label in ((PEM, "PEM-KEY"), (LEFT, "VALUE"),
                              (TOKEN, "COOKIE")):
                for m in rx.finditer(new):
                    problems.append("%s %s :: %s" % (label, path, m.group(0)[:80]))
    print("text files scanned: %d  skipped-binary: %d  redaction hits: %d"
          % (nfile, nskip, nred))
    if problems:
        print("LEFTOVERS (%d):" % len(problems))
        for p in problems[:40]:
            print(" ", p)
        return 1
    print("VERIFY PASS: no credential values found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
