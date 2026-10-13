import re
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
pat = re.compile(r"CMD_[A-Z_0-9]+")
counts = {}
seq = []
t = None
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("# event"):
            m = re.search(r"t[=:]?\s*([0-9]+(?:\.[0-9]+)?)", line)
            if m: t = m.group(1)
            continue
        if line.startswith("#"): continue
        # extract ascii strings from payload_hex
        m = re.search(r"([0-9a-fA-F]{40,})", line)
        if not m: continue
        try:
            raw = bytes.fromhex(m.group(1))
        except ValueError:
            continue
        for s in pat.findall(raw.decode("latin1")):
            counts[s] = counts.get(s, 0) + 1
            seq.append((t, s))
for s, c in sorted(counts.items(), key=lambda kv: -kv[1]):
    print("%4d  %s" % (c, s))
print("total occurrences:", sum(counts.values()))
