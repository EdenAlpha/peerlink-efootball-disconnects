import socket, ssl, json, binascii
socket.setdefaulttimeout(15)
HOST = "ntl.service.konami.net"
body = "req=" + binascii.hexlify(json.dumps(
    {"titleCode": "PES2022", "locale": "US", "version": "6.0.1",
     "extr": "", "apiLevel": "4"}, separators=(",", ":")).encode()).decode()
raw = ("POST /ntl/api/GateInfo.php HTTP/1.1\r\n"
       "Host: %s\r\n" % HOST +
       "Content-Type: application/x-www-form-urlencoded\r\n"
       "Content-Length: %d\r\n" % len(body) +
       "Connection: close\r\n\r\n" + body)
ip = socket.getaddrinfo(HOST, 80, socket.AF_INET)[0][4][0]
print("ip", ip)
s = socket.create_connection((ip, 80))
s.sendall(raw.encode())
buf = b""
while True:
    d = s.recv(65536)
    if not d:
        break
    buf += d
s.close()
head, _, b = buf.partition(b"\r\n\r\n")
print(head.decode(errors="replace"))
print("BODY len", len(b))
print(b[:2000].decode(errors="replace"))
