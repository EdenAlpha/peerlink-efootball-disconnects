import socket, ssl
socket.setdefaulttimeout(5)
host = "pes22-game.cs.konami.net"
ips = sorted({i[4][0] for i in socket.getaddrinfo(host, 443, socket.AF_INET)})
print("ips:", ips[:4])
ip = ips[0]
ctx = ssl.create_default_context()
# HTTPS 443
try:
    raw = socket.create_connection((ip, 443), timeout=5)
    s = ctx.wrap_socket(raw, server_hostname=host)
    s.sendall(("GET /ChangeServer.bin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
    buf = b""
    try:
        while True:
            c = s.recv(65536)
            if not c: break
            buf += c
            if len(buf) > 60000: break
    except socket.timeout: pass
    s.close()
    print("443 ->", len(buf), "bytes")
    print(buf[:500].decode("latin1", "replace"))
except Exception as e:
    print("443 ->", type(e).__name__, str(e)[:150])
