"""Find the body format gate_CMD_*.php actually accepts.

The captured game body (kgs-login/evidence/body.bin) is 129 bytes of RAW
MessagePack starting 0x8a (a 10-entry map) - no `req=` wrapper, no hex. But my
last test sent `req=<hex>`. That mismatch is likely why real commands 500.

This tries 4 body encodings against the SAME command (CMD_GET_SERVER_ENV,
known to exist) and reports which shape the server stops erroring on:

  A. raw msgpack bytes                (what body.bin shows)
  B. req=<hex of msgpack>             (what I sent)
  C. req=<url-encoded JSON>           (GateInfo style)
  D. raw JSON bytes                   (PACK_MODE_JSON)

Once the right shape is known, replay it on CMD_LOGIN / CMD_CREATEJOIN_ROOM.
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
MSGID = "CMD_GET_SERVER_ENV"


def fields(msgid):
    return {
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


def post(path, body, ctype):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    ip = socket.gethostbyname(HOST)
    with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=20),
                         server_hostname=HOST) as s:
        req = (
            f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
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
    head, _, pay = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    return status, pay


def main():
    import json
    import urllib.parse
    mp = packb(fields(MSGID))
    raw_json = json.dumps(fields(MSGID), separators=(",", ":")).encode()
    forms = {
        "A raw msgpack": (mp, "application/x-www-form-urlencoded"),
        "B req=hex(msgpack)": (b"req=" + mp.hex().encode(),
                              "application/x-www-form-urlencoded"),
        "C req=url(json)": (b"req=" + urllib.parse.quote_from_bytes(raw_json).encode(),
                           "application/x-www-form-urlencoded"),
        "D raw json": (raw_json, "application/json"),
        "E req=hex(json)": (b"req=" + raw_json.hex().encode(),
                           "application/x-www-form-urlencoded"),
    }
    url = f"/pes22/gate/gate_{MSGID}.php"
    for label, (body, ct) in forms.items():
        try:
            st, pay = post(url, body, ct)
            print(f"{label:24s} -> {st}")
            print(f"{'':24s}    body[{len(pay)}]: {pay[:160].decode('utf-8','replace')!r}")
        except Exception as e:
            print(f"{label:24s} -> ERR {e}")
        time.sleep(1)


if __name__ == "__main__":
    main()
