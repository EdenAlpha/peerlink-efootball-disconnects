import re
so = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native1110\libUE4.so"
pat = re.compile(rb"Cmd[A-Za-z]{3,40}\.php")
seen = set()
with open(so, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 24), b""):
        for m in pat.finditer(chunk):
            seen.add(m.group().decode())
for s in sorted(seen):
    if any(k in s.lower() for k in ("ready", "flag", "turn", "session", "relay")):
        print(s)
