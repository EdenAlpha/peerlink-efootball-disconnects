import collections
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
t0 = None
flows = {}
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#") or line.startswith("ts_ms"): continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        dirn, proto, src, sport, dst, dport = parts[1:7]
        try: ts = int(parts[0])
        except ValueError: continue
        if t0 is None: t0 = ts
        t = (ts - t0) / 1000.0
        if not (280 <= t <= 365): continue
        if dst.startswith(("10.", "192.168.", "172.")): continue
        key = (proto, dst, dport)
        if key not in flows:
            flows[key] = [t, 0]
        flows[key][1] += 1
for (proto, dst, dp), (ft, n) in sorted(flows.items(), key=lambda kv: kv[1][0]):
    print("t+%.1fs %s -> %s:%s n=%d" % (ft, proto, dst, dp, n))
