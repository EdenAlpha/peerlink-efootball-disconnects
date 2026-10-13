import re
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
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
        ts = parts[0]
        dst = parts[5] + ":" + parts[6]
        # find the http request line and host
        m = re.search(rb"(POST|GET) (\S+\.php\S*) HTTP/1\.1", raw)
        h = re.search(rb"Host: (\S+)", raw)
        clen = re.search(rb"Content-Length: (\d+)", raw)
        print("%s -> %s  %s %s len=%s" % (ts, dst,
              m.group(1).decode() if m else "?",
              m.group(2).decode() if m else "?",
              clen.group(1).decode() if clen else "?"))
        if h: print("    Host:", h.group(1).decode())
