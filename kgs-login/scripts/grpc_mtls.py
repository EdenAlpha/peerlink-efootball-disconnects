#!/usr/bin/env python3
"""gRPC + the app's bundled client identity.

Earlier we "disproved" the client cert -- but only against the PHP gate.
We never tried it on the gRPC CommandStream, which has its own CA config
(Def_Online_gRPC_debug_root_ca, Def_Online_gRPC_insecure).

Evidence it matters here:
  * valid CommandRequest -> grpc-status 14 UNAVAILABLE  (identity rejected)
  * garbage 1-byte msg   -> grpc-status 13 INTERNAL     (parser runs)
  * the binary ships CN=localhost cert + matching RSA key + CA root

Test leaf-only and full chain on the stream.
"""
from __future__ import annotations

import socket
import ssl
import struct

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
UA = "grpc-c/1.0 (android; arm64; pesam)"
BODY = open("real_body.bin", "rb").read()


def varint(v):
    o = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        o.append(b | 0x80 if v else b)
        if not v:
            return bytes(o)


def fstr(f, s):
    raw = s.encode("utf-8") if isinstance(s, str) else bytes(s)
    return bytes([f << 3 | 2]) + varint(len(raw)) + raw


def request(msgid, body, path, pack=1):
    return (fstr(1, msgid) + bytes([2 << 3 | 0]) + varint(pack)
            + fstr(3, body) + fstr(4, path))


def frame(p):
    return b"\x00" + struct.pack(">I", len(p)) + p


def call(label, payload, certfiles=None, chain=None, verify_ca=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.set_alpn_protocols(["h2"])
    if certfiles:
        ctx.load_cert_chain(*certfiles)
    sock = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=20),
                           server_hostname=HOST)
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    c = h2.connection.H2Connection(config=cfg)
    c.initiate_connection()
    sock.sendall(c.data_to_send())
    c.send_headers(1, [(":method", "POST"), (":scheme", "https"),
                       (":authority", HOST), (":path", METHOD),
                       ("content-type", "application/grpc"),
                       ("te", "trailers"), ("user-agent", UA)],
                   end_stream=False)
    c.send_data(1, frame(payload), end_stream=True)
    sock.sendall(c.data_to_send())

    sock.settimeout(12)
    status = grpc = msg = None
    out = b""
    trail = {}
    try:
        while True:
            d = sock.recv(65535)
            if not d:
                break
            for ev in c.receive_data(d):
                if isinstance(ev, h2.events.ResponseReceived):
                    h = dict(ev.headers)
                    status = h.get(":status")
                    grpc = h.get("grpc-status")
                    msg = h.get("grpc-message")
                elif isinstance(ev, h2.events.DataReceived):
                    out += ev.data
                    c.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    trail = dict(ev.headers)
                elif isinstance(ev, h2.events.StreamEnded):
                    break
            o = c.data_to_send()
            if o:
                sock.sendall(o)
            if status:
                break
    except socket.timeout:
        status = "(timeout)"
    except Exception as e:
        status = f"ERR {type(e).__name__}: {e}"
    sock.close()
    g = trail.get("grpc-status", grpc)
    m = trail.get("grpc-message", msg)
    tag = "   <<<<<< CHANGED!" if (status != "502" or g != "14") else ""
    print(f"  {label:44s} HTTP={status} grpc={g} msg={m} "
          f"body={len(out)}B{tag}", flush=True)
    if out:
        print(f"      {out[:240]!r}", flush=True)
    if trail:
        print(f"      trailers={trail}", flush=True)
    return g, out


MSG = "CMD_GET_SERVER_ENV"
P = "gate/gate_CMD_GET_SERVER_ENV.php"
REQ = request(MSG, BODY, P)

CASES = [
    ("no client cert (baseline)", None),
    ("leaf only (CN=localhost)", ("client_cert.pem", "client_key.pem")),
    ("CHAIN leaf + CA root", ("chain.pem", "chain_key.pem")),
]

for title, payload in (("CMD_GET_SERVER_ENV", REQ),
                       ("CMD_GET_KGS_GUEST_LOGIN_TOKEN",
                        request("CMD_GET_KGS_GUEST_LOGIN_TOKEN", BODY,
                                "gate/gate_CMD_GET_KGS_GUEST_LOGIN_TOKEN.php")),
                       ("CMD_LOGIN",
                        request("CMD_LOGIN", BODY,
                                "gate/gate_CMD_LOGIN.php"))):
    print(f"\n=== {title} ===", flush=True)
    for label, cf in CASES:
        try:
            call(label, payload, certfiles=cf)
        except Exception as e:
            print(f"  {label:44s} TLS-ERR {type(e).__name__}: {e}", flush=True)
