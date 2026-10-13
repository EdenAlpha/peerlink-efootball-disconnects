import re
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
n = 0
hits = {}
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#"): continue
        i = line.find('",')
        # format: ts,dir,proto,src,sport,dst,dport,ip_len,payload_hex
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        hx = parts[8]
        if len(hx) < 40: continue
        try:
            raw = bytes.fromhex(hx)
        except ValueError:
            continue
        n += 1
        # ascii strings of interest anywhere in the packet
        for pat in (b"POST ", b".php", b"CMD_", b"pesam", b"konami", b"GET "):
            if pat in raw:
                hits.setdefault(pat, 0)
                hits[pat] += 1
print("packets scanned:", n)
for k, v in sorted(hits.items(), key=lambda kv: -kv[1]):
    print("  %s -> %d packets" % (k.decode(), v))
