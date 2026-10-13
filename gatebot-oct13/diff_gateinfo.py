#!/usr/bin/env python3
"""Byte-diff our GateInfo JSON against the captured one.

NTL keeps answering STATUS:400 even with the captured header set, and the
captured Content-Length (166) is 2 bytes longer than the body we build (164).
So the JSON differs.  This decodes the captured hex and diffs it against what
chain3/probe builds, so the fix is measured, not guessed.
"""
import binascii
import json

# exact captured hex payload (after req=), from both z1 and z2 captures
CAPTURED_HEX = (
    "7b227469746c65436f6465223a2250455332303232222c226c6f63616c65223a2255"
    "53222c2276657273696f6e223a22362e302e31222c226578747261223a22222c2261"
    "70694c6576656c223a2234227d")

cap_json = binascii.unhexlify(CAPTURED_HEX).decode("latin1")
cap_body = ("req=" + CAPTURED_HEX).encode()

built_json = json.dumps(
    {"titleCode": "PES2022", "locale": "US", "version": "6.0.1",
     "extr": "", "apiLevel": "4"}, separators=(",", ":"))
built_body = ("req=" + binascii.hexlify(built_json.encode()).decode()).encode()

print("captured JSON (%d bytes): %s" % (len(cap_json), cap_json))
print("built    JSON (%d bytes): %s" % (len(built_json), built_json))
print("captured body: %d bytes   built body: %d bytes" % (
    len(cap_body), len(built_body)))
print("-" * 74)
print("identical: %s" % (cap_json == built_json))

if cap_json != built_json:
    kc = json.loads(cap_json)
    kb = json.loads(built_json)
    print("\ncaptured keys: %s" % list(kc))
    print("built    keys: %s" % list(kb))
    for k in kc:
        if k not in kb:
            print("  MISSING in ours: %r = %r" % (k, kc[k]))
    for k in kb:
        if k not in kc:
            print("  EXTRA   in ours: %r = %r" % (k, kb[k]))
    for k in kc:
        if k in kb and kc[k] != kb[k]:
            print("  DIFFERS %r: captured=%r built=%r" % (k, kc[k], kb[k]))
