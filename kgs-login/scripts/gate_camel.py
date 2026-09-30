"""Test the CORRECT CamelCase command URL the game actually builds.

Evidence (run_gateinfo / real_a.txt) shows the game's URL composer builds:
    https://pes22-game.cs.konami.net/pes22/gate/gate_CmdGetServerEnv.php
That is CamelCase `Cmd*`, while every earlier probe used `CMD_*` (underscore,
uppercase) - a DIFFERENT name. That mismatch is the prime suspect for the
blanket 500s.

This hits the CamelCase gate URLs with the game's real MessagePack body and
prints the raw response. If any returns data (not empty '0'), that's the door.
"""
import os
import socket
import ssl
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from msgpack import enc as packb  # local module  # noqa: E402

HOST = "pes22-game.cs.konami.net"


def body(msgid):
    return packb({
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
    })


def post(path, data, ctype="application/x-www-form-urlencoded"):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    ip = socket.gethostbyname(HOST)
    with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=20),
                         server_hostname=HOST) as s:
        req = (
            f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Content-Type: {ctype}\r\nContent-Length: {len(data)}\r\n"
            f"User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        s.sendall(req + data)
        out = b""
        try:
            while True:
                c = s.recv(65535)
                if not c:
                    break
                out += c
        except Exception:
            pass
    head, _, pay = out.partition(b"\r\n\r\n")
    return head.split(b"\r\n", 1)[0].decode(errors="replace"), pay


def main():
    urls = [
        "/pes22/gate/gate_CmdGetServerEnv.php",
        "/pes22/CmdGetServerEnv.php",
        "/pes22/gate/gate_CmdLogin.php",
        "/pes22/gate/gate_CmdCreateJoinRoom.php",
        "/pes22/gate/gate_CmdGetRoomList.php",
    ]
    for u in urls:
        msgid = u.rsplit("/", 1)[-1].replace("gate_", "").replace(".php", "")
        # body msgid in the captured game body is UPPERCASE even for the
        # CamelCase URL - test both the raw name and the URL name
        for b_id in (msgid, msgid.upper()):
            data = b"req=" + body(b_id).hex().encode()
            try:
                st, pay = post(u, data)
                print(f"{u:42s} msgid={b_id:26s} {st}  body[{len(pay)}]={pay[:120]!r}")
            except Exception as e:
                print(f"{u:42s} msgid={b_id:26s} ERR {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()
