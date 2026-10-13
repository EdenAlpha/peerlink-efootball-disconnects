import re
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
t0 = None
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#"): continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        dirn, proto, src, sport, dst, dport = parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
        hx = parts[8]
        if len(hx) < 40: continue
        try:
            raw = bytes.fromhex(hx)
        except ValueError:
            continue
        ts = int(parts[0])
        if t0 is None: t0 = ts
        # responses from the NTL hosts
        if src in ("35.174.175.11", "34.193.147.150") and b"HTTP/1.1" in raw:
            head_end = raw.find(b"\r\n\r\n")
            body = raw[head_end+4:] if head_end > 0 else b""
            status = re.search(rb"HTTP/1\.1 (\d+)", raw)
            print("=== RESP t+%.1fs from %s:%s status=%s body=%d" %
                  ((ts-t0)/1000.0, src, sport,
                   status.group(1).decode() if status else "?", len(body)))
            if body:
                print(body[:700].decode("latin1", "replace"))
            print()
