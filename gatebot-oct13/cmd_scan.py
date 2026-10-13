import re
so = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
pat = re.compile(rb"CMD_[A-Z0-9_]{4,60}")
seen = set()
with open(so, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 24), b""):
        for m in pat.finditer(chunk):
            s = m.group().decode()
            if s not in seen:
                seen.add(s)
for s in sorted(seen):
    if any(k in s for k in ("READY", "PUNCH", "STUN", "NTL", "ESTABLISH", "TURN", "RELAY", "SESSION", "GAME")):
        print(s)
