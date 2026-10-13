import re
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
t0 = None
n = 0
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
        if dirn == "r" and b"HTTP/1" in raw:
            n += 1
            src = parts[3] + ":" + parts[4]
            status = re.search(rb"HTTP/1\.[01] (\d+)", raw)
            head_end = raw.find(b"\r\n\r\n")
            body = raw[head_end+4:] if head_end > 0 else b""
            snippet = body[:200].decode("latin1", "replace").replace("\r", " ").replace("\n", " ")
            print("t+%.1fs %s st=%s blen=%d %s" % ((ts-t0)/1000.0, src,
                  status.group(1).decode() if status else "?", len(body), snippet[:150]))
print("total r-dir http packets:", n)
