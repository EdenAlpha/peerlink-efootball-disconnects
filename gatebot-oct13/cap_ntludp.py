f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
# the sustained GCP flows (candidate NTL session sockets)
targets = {("34.22.210.195","30970"), ("35.240.102.10","31406"),
           ("35.233.88.176","32741"), ("34.156.177.234","31840")}
t0 = None
rows = []
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#") or line.startswith("ts_ms"): continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        dirn, proto, src, sport, dst, dport = parts[1:7]
        try: ts = int(parts[0])
        except ValueError: continue
        if t0 is None: t0 = ts
        if proto != "udp": continue
        if (dst, dport) in targets or (src, sport) in targets:
            try: raw = bytes.fromhex(parts[8])
            except ValueError: continue
            pl = raw[28:] if len(raw) > 28 else b""
            rows.append(((ts-t0)/1000.0, dirn, src, sport, dst, dport, pl))
print("packets in candidate NTL flows:", len(rows))
# show first 12 packets of each flow
seen = {}
for t, d, src, sp, dst, dp, pl in rows:
    key = (dst, dp) if d == "t" else (src, sp)
    seen.setdefault(key, 0)
    if seen[key] >= 10: continue
    seen[key] += 1
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in pl[:60])
    print("%9.3fs %s %-21s -> %-21s len=%-4d %s" %
          (t, d, src+":"+sp, dst+":"+dp, len(pl), pl[:48].hex()))
    print("           ascii: %s" % asc)
