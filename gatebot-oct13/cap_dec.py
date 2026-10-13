#!/usr/bin/env python3
"""cap_dec.py -- decrypt captured gate request/response blocks.

usage: python cap_dec.py [CMD ...]      (default: every captured command)

Decrypts REQ/RESP hex from the committed gate capture (real phone traffic)
and prints envelope + body structure with credential values masked.
ALWAYS pipe through redact.py:

  python cap_dec.py CMD_SET_PLAYDATA_MATCH 2>&1 | python redact.py
"""
import gzip
import re
import sys
import zlib

import msgpack
from Crypto.Cipher import AES

KEY_B = bytes.fromhex(
    "43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\kgs-login\captures"
       r"\2026-10-01-gate\gate-login-exchange.txt")

ENVELOPE = ("msgid", "rqid", "user_id", "session_id", "my_platform",
            "s_keyword", "lang", "region", "platform", "client_version")

SENS = {"user_id", "session_id", "s_keyword", "auth_code", "user_code",
        "sign", "serial", "account_id", "password", "auth_key", "auth_token"}


def dec(body: bytes) -> dict:
    iv, ct = body[:16], body[16:]
    pt = AES.new(KEY_B, AES.MODE_CBC, iv).decrypt(ct)
    pt = pt[:-pt[-1]]
    raw = gzip.decompress(pt) if pt[:2] == b"\x1f\x8b" else zlib.decompress(pt)
    try:
        return msgpack.unpackb(raw, raw=False, strict_map_key=False)
    except TypeError:                               # old msgpack
        return msgpack.unpackb(raw, raw=False)


def brief(v, depth=0):
    if isinstance(v, str):
        return repr(v) if len(v) <= 64 else "str(len=%d)" % len(v)
    if isinstance(v, (int, float, bool)) or v is None:
        return repr(v)
    if isinstance(v, dict):
        return "{%s}" % ", ".join(str(k) for k in v)
    if isinstance(v, list):
        return "[%d x %s]" % (len(v), brief(v[0], depth + 1) if v else "-")
    return type(v).__name__


def show(tag, msg):
    if not isinstance(msg, dict):
        print("%s: <not a map> %s" % (tag, brief(msg)))
        return
    keys = list(msg)
    print("%s: %d keys" % (tag, len(keys)))
    env = [k for k in keys if k in ENVELOPE]
    body = [k for k in keys if k not in ENVELOPE]
    print("  envelope order: %s" % env)
    for k in env:
        v = msg[k]
        if k in SENS:
            print("    %-16s = <len=%d>" % (k, len(str(v))))
        else:
            print("    %-16s = %s" % (k, brief(v)))
    extra_env = [k for k in keys if k not in ENVELOPE and k in
                 ("game_id", "room_id", "match_id", "rq_result")]
    print("  body keys (%d): %s" % (len(body), body))
    for k in body:
        v = msg[k]
        if k in SENS:
            print("    %-28s = <redacted>" % k)
        else:
            print("    %-28s : %s" % (k, brief(v)))


def main():
    want = set(a.upper() for a in sys.argv[1:])
    txt = open(CAP, encoding="utf-8", errors="replace").read()
    txt = txt.replace("\r\n", "\n")
    blocks = re.split(r"(?=^### )", txt, flags=re.M)
    seen = {}
    for b in blocks:
        mh = re.match(r"### (REQ|RESP) POST /pes22/gate/gate_(\w+)\.php"
                      r"(?: -> (\d+))?", b)
        if not mh:
            continue
        kind, cmd, code = mh.group(1), mh.group(2), mh.group(3)
        me = re.search(r"^(?:REQ|RESP)HEX: ([0-9a-f]+)\s*$", b, flags=re.M)
        if not me:
            continue
        key = (cmd, kind)
        if key in seen:
            continue
        seen[key] = True
        if want and cmd.upper() not in want:
            continue
        try:
            msg = dec(bytes.fromhex(me.group(1)))
        except Exception as e:                       # noqa: BLE001
            print("%s %s: DECRYPT FAIL %s" % (kind, cmd, e))
            continue
        tag = "%s %s%s" % (kind, cmd, " -> %s" % code if code else "")
        show(tag, msg)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
