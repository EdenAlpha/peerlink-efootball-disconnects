import re
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
t0 = None
names = {}
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#") or line.startswith("ts_ms"): continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        proto = parts[2]
        try: ts = int(parts[0])
        except ValueError: continue
        if t0 is None: t0 = ts
        if proto != "udp": continue
        try: raw = bytes.fromhex(parts[8])
        except ValueError: continue
        # DNS over UDP: sport or dport 53; parse qname
        sport, dport = parts[4], parts[6]
        if "53" not in (sport, dport): continue
        pl = raw[28:] if len(raw) > 28 else b""
        if len(pl) < 12: continue
        # qname at offset 12
        i = 12
        labels = []
        try:
            while pl[i] != 0:
                L = pl[i]; i += 1
                labels.append(pl[i:i+L].decode("ascii", "replace"))
                i += L + 1
            name = ".".join(labels)
            if name and name not in names:
                names[name] = (ts - t0) / 1000.0
        except Exception:
            pass
for n, t in sorted(names.items(), key=lambda kv: kv[1]):
    print("t+9.1fs %s" % (t, n) if False else "t+%.1fs %s" % (t, n))
