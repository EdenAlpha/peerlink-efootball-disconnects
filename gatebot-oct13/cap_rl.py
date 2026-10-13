import re, urllib.parse
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
t0 = None
seen = set()
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#"): continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        hx = parts[8]
        if len(hx) < 40: continue
        try:
            raw = bytes.fromhex(hx)
        except ValueError:
            continue
        if b"ReportLog" not in raw: continue
        ts = int(parts[0])
        if t0 is None: t0 = ts
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
        # urlencoded: key=hex
        txt = body.decode("latin1", "replace")
        kv = {}
        for pair in txt.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                try:
                    kv[k] = bytes.fromhex(v).decode("utf-8", "replace")
                except ValueError:
                    kv[k] = v
        key = tuple(sorted((k, v[:80]) for k, v in kv.items()))
        if key in seen: continue
        seen.add(key)
        print("=== t+%.1fs ReportLog (%d bytes)" % ((ts - t0) / 1000.0, len(body)))
        for k, v in kv.items():
            print("  %s = %s" % (k, v[:900]))
