import socket, ssl, time
host = "pes22-game.cs.konami.net"
# 1) TCP connect probes on candidate ports
for port in (12034, 559, 443, 80):
    for proto_name, fam in (("tcp", socket.SOCK_STREAM),):
        try:
            s = socket.create_connection((host, port), timeout=6)
            print("%s:%d OPEN" % (host, port))
            s.settimeout(6)
            if port in (12034, 559):
                # try a plain GET
                s.sendall(("GET /ChangeServer.bin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
                buf = b""
                try:
                    while True:
                        c = s.recv(65536)
                        if not c: break
                        buf += c
                        if len(buf) > 20000: break
                except socket.timeout:
                    pass
                print("  plain GET -> %d bytes: %r" % (len(buf), buf[:300]))
            s.close()
        except Exception as e:
            print("%s:%d ERR %s" % (host, port, type(e).__name__))
