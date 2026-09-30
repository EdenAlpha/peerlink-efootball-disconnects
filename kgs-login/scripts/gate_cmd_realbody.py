"""Send a REAL body to the game's PHP gate commands and read the answer.

Earlier work proved the gate discriminates: `gate_CMD_X.php` returns 500 for
commands that exist (payload rejected) vs 404 for ones that don't. But that
used an EMPTY/wrong body. The game's real body is MessagePack (captured from
the running game, kgs-login/evidence/body.bin) with `msgid` naming the command.

This replays that exact body shape but swaps in CMD_LOGIN / CMD_CREATEJOIN_ROOM
and reads what Konami says. If a command wants specific fields, the error text
tells us which - which is how we learn the room-create contract without ever
seeing the game's own screen.

Reference body (MSGPACK, from the game):
  {'msgid','rqid','user_id','session_id','my_platform','s_keyword',
   'lang','region','platform','client_version'}
"""
import json
import os
import socket
import ssl
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# NOTE: msgpack.py in THIS folder is the project's own minimal encoder (enc()),
# and it shadows the pip `msgpack` package when run from here. Use it directly.
from msgpack import enc as packb  # noqa: E402  (local module, not the pip one)

HOST = "pes22-game.cs.konami.net"


def base_body(msgid: str, **over):
    d = {
        "msgid": msgid,
        "rqid": 1,
        "user_id": 0,
        "session_id": "",
        "my_platform": "",
        "s_keyword": "",
        "lang": "en",
        "region": "US",
        "platform": "PES",
        "client_version": "6.0.1",
    }
    d.update(over)
    return packb(d)


def post(path: str, body: bytes, ctype="application/x-www-form-urlencoded"):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    ip = socket.gethostbyname(HOST)
    with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=20),
                         server_hostname=HOST) as s:
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {HOST}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        s.sendall(req + body)
        data = b""
        try:
            while True:
                c = s.recv(65535)
                if not c:
                    break
                data += c
        except Exception:
            pass
    return data


def main():
    targets = [
        ("CMD_GET_SERVER_ENV", "control: known-working"),
        ("CMD_LOGIN", "login"),
        ("CMD_CREATEJOIN_ROOM", "create/join room"),
        ("CMD_GET_ROOM_LIST", "room list"),
        ("CMD_GET_KGS_GUEST_LOGIN_TOKEN", "guest login token"),
        ("CMD_BOGUS_DOES_NOT_EXIST", "control: must be 404"),
    ]
    for msgid, label in targets:
        url = f"/pes22/gate/gate_{msgid}.php"
        body = b"req=" + base_body(msgid).hex().encode()
        for attempt in range(3):
            try:
                raw = post(url, body)
                head, _, pay = raw.partition(b"\r\n\r\n")
                status = head.split(b"\r\n", 1)[0].decode(errors="replace")
                print(f"{msgid:34s} {label:22s}")
                print(f"   {status}")
                print(f"   body: {pay[:300].decode('utf-8', 'replace')}")
                break
            except Exception as e:
                print(f"{msgid:34s} attempt {attempt}: {e}")
                time.sleep(2)


if __name__ == "__main__":
    main()
