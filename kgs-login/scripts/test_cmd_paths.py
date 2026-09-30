"""DECISIVE TEST: are the CMD_* names the hidden gRPC `path` values?

From msgid.txt: CMD_* literals in the binary, probed at Konami's PHP gate
return 500 (route exists) or 404 (doesn't). The gate PHP and the gRPC
CommandStream are two interfaces to the same command dispatch. If the gRPC
`path` accepts these names, the server's answer must NOT be the generic
unknown-route failure (grpc-status 14 / HTTP 502).

We send each name 5+ times (endpoint transient ~0.7%) and classify the
response, using the game's own client from kgs_client.py.
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from kgs_client import command_request, command_response, varint_read  # noqa

HOST = "pes22-game.cs.konami.net"
PORT = 443
RPC = "/command_service.CommandService/CommandStream"


def send(path: str, payload: str = "{}"):
    import socket
    import ssl
    import struct
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    raw = socket.create_connection((HOST, PORT), timeout=20)
    tls = ctx.wrap_socket(raw, server_hostname=HOST)
    assert tls.selected_alpn_protocol() == "h2", tls.selected_alpn_protocol()
    # minimal h2: preface + settings + headers + one request message
    from decode_capture import hpack_decode  # noqa: F401  (proves lib present)
    import h2.connection
    import h2.config
    import h2.events
    cfg = h2.config.H2Configuration(client_side=True, header_encoding=None)
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    tls.sendall(conn.data_to_send())
    hdrs = [
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":path", RPC.encode()),
        (b":authority", HOST.encode()),
        (b"te", b"trailers"),
        (b"content-type", b"application/grpc"),
        (b"user-agent", b"grpc-c++/1.30.0"),
    ]
    body = b"\x00" + struct.pack(">I", len(command_request("t", path, payload))) \
        + command_request("t", path, payload)
    conn.send_headers(1, hdrs, end_stream=False)
    conn.send_data(1, body, end_stream=True)
    tls.sendall(conn.data_to_send())
    resp = b""
    status = headers = None
    deadline = time.time() + 25
    while time.time() < deadline:
        tls.settimeout(max(1, deadline - time.time()))
        try:
            chunk = tls.recv(65535)
        except Exception:
            break
        if not chunk:
            break
        for ev in conn.receive_data(chunk):
            if isinstance(ev, h2.events.ResponseReceived):
                status = dict(ev.headers).get(b":status", b"?").decode()
                headers = {k: v for k, v in ev.headers}
            elif isinstance(ev, h2.events.DataReceived):
                resp += ev.data
                conn.acknowledge_received_data(len(ev.data), ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                deadline = 0
        out = conn.data_to_send()
        if out:
            tls.sendall(out)
        if deadline == 0:
            break
    try:
        tls.close()
    except Exception:
        pass
    gstatus = (headers or {}).get(b"grpc-status", b"").decode()
    gmsg = (headers or {}).get(b"grpc-message", b"").decode()
    return status, gstatus, gmsg, resp


def classify(resp: bytes):
    """Find the CommandResponse res field inside the grpc frame."""
    if not resp:
        return None
    # frame: 1 byte compressed-flag + 4 byte length + protobuf
    if resp[0] == 0 and len(resp) >= 5:
        n = int.from_bytes(resp[1:5], "big")
        msg = resp[5:5 + n]
    else:
        msg = resp
    try:
        out = command_response(msg)
        return out
    except Exception:
        return {"_raw": msg[:200].hex()}


def main():
    names = [
        "CMD_GET_SERVER_ENV",
        "CMD_LOGIN",
        "CMD_CREATEJOIN_ROOM",
        "CMD_GET_ROOM_LIST",
        "CMD_GET_KGS_GUEST_LOGIN_TOKEN",
        "CMD_BOGUS_DOES_NOT_EXIST",
    ]
    for name in names:
        codes = []
        detail = ""
        for attempt in range(5):
            try:
                st, gs, gm, body = send(name)
            except Exception as e:
                codes.append("ERR")
                detail = str(e)[:80]
                time.sleep(2)
                continue
            codes.append(f"http={st},grpc={gs or '-'}")
            if body:
                detail = str(classify(body))[:120]
            elif gm:
                detail = gm[:120]
            time.sleep(1)
        uniq = sorted(set(codes))
        print(f"{name:38s} {uniq} {detail}")


if __name__ == "__main__":
    main()
