import re, urllib.parse
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
t0 = None
shown = set()
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#"): continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        dirn = parts[1]
        hx = parts[8]
        if len(hx) < 40: continue
        try:
            raw = bytes.fromhex(hx)
        except ValueError:
            continue
        ts = int(parts[0])
        if t0 is None: t0 = ts
        if dirn == "t" and b"ReportLog" in raw:
            body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
            txt = body.decode("latin1", "replace")
            typ = None
            dat = None
            for pair in txt.split("&"):
                if pair.startswith("type="):
                    typ = pair[5:]
                elif pair.startswith("dat="):
                    v = pair[4:]
                    try:
                        dat = bytes.fromhex(v).decode("utf-8", "replace")
                    except ValueError:
                        dat = urllib.parse.unquote(v)
            if typ in shown: continue
            shown.add(typ)
            print("===== type=%s t+%.1fs dat =====" % (typ, (ts-t0)/1000.0))
            print((dat or "")[:1400])
            print()
