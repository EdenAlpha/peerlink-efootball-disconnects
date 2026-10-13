#!/usr/bin/env python3
"""ws_strings.py -- locate the game's WebSocket client + payload formats.

Hunts: Sec-WebSocket-* literals (client upgrade builder), websocket lib
source paths, JSON register format fragments, then NUL-terminated
copies ready for xref.
"""
import re

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk"
      r"\native1110\libUE4.so")

data = open(SO, "rb").read()

patterns = [
    rb"Sec-WebSocket[A-Za-z-]*",
    rb"[A-Za-z0-9_./\\-]{4,140}(?:libwebsockets|websocketpp|WebSockets?)[A-Za-z0-9_./\\-]{0,60}\.(?:c|h|cpp|cc)\x00",
    rb"\"name\"\s*:",
    rb"\{\s*\"name\"",
    rb"\"token\"\s*:",
    rb"Upgrade: websocket",
    rb"websocket",
    rb"[Ww]eb[Ss]ocket[^\x00]{0,40}",
]

seen = set()
for pat in patterns:
    for m in re.finditer(pat, data):
        s = m.group()
        try:
            t = s.decode(errors="replace")
        except Exception:
            t = repr(s)
        if t in seen:
            continue
        seen.add(t)
        off = m.start()
        # classify
        kind = ""
        if s.endswith(b"\x00"):
            kind = "NUL"
        if b"Sec-WebSocket" in s:
            kind = "HDR " + kind
        print("  0x%08x %-6s %r" % (off, kind, t[:110]))
        if len(seen) > 140:
            break
    if len(seen) > 140:
        break
print("total: %d" % len(seen))
