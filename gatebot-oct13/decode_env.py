#!/usr/bin/env python3
"""decode_env.py -- decode the base64 config blobs from CMD_GET_SERVER_ENV.

CMD_GET_SERVER_ENV (run #17, NOERR for both identities) returns two base64
fields, `proto_opt` and `onsys_opt`, which are JSON.  `onsys_opt` is the
authoritative server-side config: the per-command in-match timeout table, the
timeout_settings block, and the task on/off switches.

Read-only.  Usage: python decode_env.py <log>
"""
import base64
import json
import re
import sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "chain_run17.log"


def shapes(o, depth=0):
    """Render a decoded config compactly, preserving key order."""
    pad = "    " * depth
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(v, (dict, list)):
                print("%s%s:" % (pad, k))
                shapes(v, depth + 1)
            else:
                print("%s%s = %r" % (pad, k, v))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            if isinstance(v, (dict, list)):
                print("%s[%d]:" % (pad, i))
                shapes(v, depth + 1)
            else:
                print("%s[%d] = %r" % (pad, i, v))
    else:
        print("%s%r" % (pad, o))


def read_text(path):
    """chain_run*.log is written by PowerShell `*>`, which emits UTF-16 for
    some streams -- detect it rather than assuming utf-8."""
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw[:2] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-16-le", errors="replace")


def main():
    txt = read_text(LOG)
    for field in ("proto_opt", "onsys_opt"):
        m = re.search(re.escape(field) + r"\s*=\s*([A-Za-z0-9+/=]{40,})", txt)
        if not m:
            print("!! %s not found in %s" % (field, LOG))
            continue
        b64 = m.group(1)
        raw = base64.b64decode(b64)
        print("=" * 70)
        print("%s  (%d b64 chars -> %d bytes)" % (field, len(b64), len(raw)))
        print("=" * 70)
        try:
            j = json.loads(raw.decode("utf-8"))
        except Exception as e:
            print("  decode failed: %s" % e)
            print(raw[:400])
            continue
        shapes(j)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
