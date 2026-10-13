import urllib.parse
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
t0 = None
seen = set()
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#") or line.startswith("ts_ms"): continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        dirn = parts[1]
        try: ts = int(parts[0])
        except ValueError: continue
        if t0 is None: t0 = ts
        if dirn != "t": continue
        try: raw = bytes.fromhex(parts[8])
        except ValueError: continue
        if b"ReportLog" not in raw: continue
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
        txt = body.decode("latin1", "replace")
        kv = {}
        for pair in txt.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                kv[k] = v
        typ = kv.get("type")
        if typ in seen: continue
        seen.add(typ)
        v = kv.get("dat", "")
        try:
            dat = bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            dat = urllib.parse.unquote(v)
        print("===== type=%s prefix=%s" % (typ, kv.get("prefix")))
        print(dat)
        print()
