import socket
socket.setdefaulttimeout(5)
# extract the exact first DTLS ClientHello from the capture
f = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"
hello = None
with open(f, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.startswith("#") or line.startswith("ts_ms"): continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9: continue
        if parts[5] == "34.22.210.195" and parts[6] == "30970":
            try: raw = bytes.fromhex(parts[8])
            except ValueError: continue
            hello = raw[28:]  # strip IP+UDP
            break
print("captured ClientHello: %d bytes" % len(hello))
print(hello[:40].hex())
host = "pes22-game.cs.konami.net"
ips = sorted({i[4][0] for i in socket.getaddrinfo(host, 559, socket.AF_INET)})
ip = ips[0]
print("target:", ip)
for port in (559, 12034):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(hello, (ip, port))
        try:
            data, addr = s.recvfrom(4096)
            print("UDP %d <- %d bytes from %s: %s" % (port, len(data), addr, data[:60].hex()))
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:80])
            print("   ascii:", asc)
        except socket.timeout:
            print("UDP %d <- timeout (no reply)" % port)
        s.close()
    except Exception as e:
        print("UDP %d -> %s %s" % (port, type(e).__name__, str(e)[:100]))
