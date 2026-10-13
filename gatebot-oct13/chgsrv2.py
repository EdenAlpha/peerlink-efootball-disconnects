import socket, ssl, binascii
socket.setdefaulttimeout(15)
HOST = "info.service.konami.net"
PATHS = ["/XWW020-E1/info/ChangeServer.bin",
         "/XWW020-E1/info/",
         "/XWW020-E1/info/changeServer.bin"]
ctx = ssl.create_default_context()
for p in PATHS:
    try:
        ip = socket.getaddrinfo(HOST, 443, socket.AF_INET)[0][4][0]
        s = socket.create_connection((ip, 443))
        c = ctx.wrap_socket(s, server_hostname=HOST)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: okhttp/3.12.4\r\n"
               "Connection: close\r\n\r\n" % (p, HOST))
        c.sendall(req.encode())
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
        c.close()
        head, _, body = buf.partition(b"\r\n\r\n")
        print("PATH", p, "->", head.split(b"\r\n")[0].decode(errors="replace"),
              "len", len(body))
        if body:
            print("  body[0:200]", body[:200])
    except Exception as e:
        print("PATH", p, "ERR", e)
