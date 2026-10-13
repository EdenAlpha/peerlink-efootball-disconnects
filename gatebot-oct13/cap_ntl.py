import re
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
t0 = None
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
        if b".php" not in raw: continue
        ts = int(parts[0])
        if t0 is None: t0 = ts
        m = re.search(rb"(POST|GET) (\S+) HTTP/1\.1", raw)
        url = m.group(2).decode() if m else "?"
        if "GateInfo" not in url and "ReportLog" not in url: continue
        # full body after \r\n\r\n
        body = b""
        if b"\r\n\r\n" in raw:
            body = raw.split(b"\r\n\r\n", 1)[1]
        hdr_end = raw.find(b"\r\n\r\n")
        head = raw[:hdr_end].decode("latin1") if hdr_end > 0 else ""
        if "GateInfo" in url:
            print("=== t+%.1fs %s" % ((ts - t0) / 1000.0, url))
            print(head)
            print("--- body (%d bytes) ---" % len(body))
            print(body[:600].decode("latin1", "replace"))
        else:
            print("t+%.1fs ReportLog len=%d head-CT=%s" %
                  ((ts - t0) / 1000.0, len(body),
                   "Content-Type" in head and re.search(r"Content-Type: (\S+)", head).group(1) or "?"))
