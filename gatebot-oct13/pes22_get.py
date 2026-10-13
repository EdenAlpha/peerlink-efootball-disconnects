import socket, ssl
socket.setdefaulttimeout(6)
host = "pes22-game.cs.konami.net"
ctx = ssl.create_default_context()
for port, use_tls in ((443, True), (559, True), (559, False), (12034, False)):
    tag = "%s:%d tls=%s" % (host, port, use_tls)
    try:
        s = socket.create_connection((host, port), timeout=5)
        if use_tls:
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(("GET /ChangeServer.bin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
        buf = b""
        try:
            while True:
                c = s.recv(65536)
                if not c: break
                buf += c
                if len(buf) > 60000: break
        except socket.timeout:
            pass
        s.close()
        head = buf.split(b"\r\n\r\n", 1)[0][:400]
        print("=== %s -> %d bytes" % (tag, len(buf)))
        print(head.decode("latin1", "replace"))
        body = buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""
        print("body[%d]: %r" % (len(body), body[:200]))
    except Exception as e:
        print("=== %s -> %s %s" % (tag, type(e).__name__, str(e)[:120]))
