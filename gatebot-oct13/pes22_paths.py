import socket, ssl
socket.setdefaulttimeout(5)
host = "pes22-game.cs.konami.net"
ips = sorted({i[4][0] for i in socket.getaddrinfo(host, 443, socket.AF_INET)})
ip = ips[0]
ctx = ssl.create_default_context()
paths = ["/pes22/ChangeServer.bin", "/PES22/ChangeServer.bin",
         "/ChangeServer.bin?", "/game/ChangeServer.bin",
         "/pes22-game/ChangeServer.bin", "/dl/ChangeServer.bin",
         "/config/ChangeServer.bin", "/bin/ChangeServer.bin"]
for p in paths:
    try:
        raw = socket.create_connection((ip, 443), timeout=5)
        s = ctx.wrap_socket(raw, server_hostname=host)
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (p, host)).encode())
        buf = b""
        try:
            while True:
                c = s.recv(65536)
                if not c: break
                buf += c
                if len(buf) > 100000: break
        except socket.timeout: pass
        s.close()
        status = buf.split(b"\r\n", 1)[0][:60]
        print("%-32s -> %s (%d bytes)" % (p, status.decode("latin1","replace"), len(buf)))
    except Exception as e:
        print("%-32s -> %s" % (p, type(e).__name__))
