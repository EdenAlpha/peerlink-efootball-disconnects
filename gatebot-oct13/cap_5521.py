import collections
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
t0 = None
pkts = []
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#") or line.startswith("ts_ms"): continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        dirn, proto, src, sport, dst, dport = parts[1:7]
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        if t0 is None: t0 = ts
        if proto != "udp" or dport != "5521": continue
        try:
            raw = bytes.fromhex(parts[8])
        except ValueError:
            continue
        # strip IP(20)+UDP(8) headers -> payload
        if len(raw) < 28: continue
        pl = raw[28:]
        pkts.append(((ts-t0)/1000.0, dirn, dst, sport, pl))
print("udp/5521 packets:", len(pkts))
# one full exchange with the first server
target = pkts[0][2]
ex = [p for p in pkts if p[2] == target][:8]
for t, d, dst, sp, pl in ex:
    print("--- t+%.3fs %s -> %s sport=%s len=%d" % (t, d, dst, sp, len(pl)))
    print(pl[:120].hex())
    # ascii view
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in pl[:120])
    print(asc)
