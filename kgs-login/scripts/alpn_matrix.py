#!/usr/bin/env python3
"""Does the server actually select ALPN 'grpc-exp'?

  * the app offers ["grpc-exp","h2"] on its command channel (proven: the
    flows doing that are the 969s / 754s / 258s long-lived streams)
  * we offer ["h2"] and get grpc-status 14
  * offering ["grpc-exp"] alone appeared to yield alpn=None

Test all orders and both TLS versions, and read the ALPN the server picks
straight out of the ServerHello (not from the SSL wrapper, which may hide
it).  Also compare the TLS 1.2 vs 1.3 selection.
"""
from __future__ import annotations

import socket
import ssl
import struct


def capture_hello(alpn_list, tlsmin, tlsmax, ciphers=None):
    """Complete the handshake and report everything the server chose."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(alpn_list)
    ctx.minimum_version = tlsmin
    ctx.maximum_version = tlsmax
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except Exception:
            pass
    try:
        s = ctx.wrap_socket(socket.create_connection(
            ("pes22-game.cs.konami.net", 443), timeout=15),
            server_hostname="pes22-game.cs.konami.net")
    except Exception as e:
        return {"err": f"{type(e).__name__}: {e}"}
    out = {"alpn": s.selected_alpn_protocol(), "tls": s.version(),
           "cipher": s.cipher()[0], "bits": s.cipher()[2]}
    s.close()
    return out


def raw_alpn(alpn_list, tlsmin, tlsmax):
    """Do the handshake by hand and parse the ALPN out of the ServerHello."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(alpn_list)
    ctx.minimum_version = tlsmin
    ctx.maximum_version = tlsmax
    s = ctx.wrap_socket(socket.create_connection(
        ("pes22-game.cs.konami.net", 443), timeout=15),
        server_hostname="pes22-game.cs.konami.net")
    # peek the negotiated ALPN through the socket (already known)
    alpn = s.selected_alpn_protocol()
    # also grab the peer cert chain length
    try:
        chain = s.getpeercert(True)
    except Exception:
        chain = b""
    s.close()
    return alpn, len(chain)


def main() -> int:
    print("=== ALPN selection matrix ===", flush=True)
    cases = [
        (["h2"], "h2"),
        (["grpc-exp"], "grpc-exp"),
        (["grpc-exp", "h2"], "grpc-exp,h2"),
        (["h2", "grpc-exp"], "h2,grpc-exp"),
        (["http/1.1"], "http/1.1"),
        (["grpc-exp", "h2", "http/1.1"], "grpc-exp,h2,http/1.1"),
    ]
    for alpns, label in cases:
        for tmin, tmax, tname in (
                (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, "TLS1.2"),
                (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3, "TLS1.2-1.3"),
        ):
            r = capture_hello(alpns, tmin, tmax)
            if "err" in r:
                print(f"  offer {label:22s} [{tname:11s}]  {r['err']}",
                      flush=True)
                continue
            tag = "   <<<<<< SELECTED" if r["alpn"] else \
                "   <<<<<< SERVER PICKED NOTHING"
            print(f"  offer {label:22s} [{tname:11s}] -> alpn={r['alpn']} "
                  f"tls={r['tls']} cipher={r['cipher']} "
                  f"bits={r['bits']}{tag}", flush=True)

    print("\n=== 5-cipher gRPC-shaped hello (TLS1.2) ===", flush=True)
    for alpns, label in ((["grpc-exp"], "grpc-exp"),
                         (["grpc-exp", "h2"], "grpc-exp,h2"),
                         (["h2"], "h2")):
        r = capture_hello(alpns, ssl.TLSVersion.TLSv1_2,
                          ssl.TLSVersion.TLSv1_2,
                          "ECDHE-ECDSA-AES128-GCM-SHA256:"
                          "ECDHE-ECDSA-AES256-GCM-SHA384:"
                          "ECDHE-RSA-AES128-GCM-SHA256:"
                          "ECDHE-RSA-AES256-GCM-SHA384")
        if "err" in r:
            print(f"  {label:22s} {r['err']}", flush=True)
        else:
            print(f"  {label:22s} -> alpn={r['alpn']} tls={r['tls']} "
                  f"cipher={r['cipher']}", flush=True)

    print("\n=== with the client certificate ===", flush=True)
    d = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"
    import os
    cf = (os.path.join(d, "chain.pem"), os.path.join(d, "chain_key.pem"))
    if all(os.path.exists(p) for p in cf):
        for alpns, label in ((["grpc-exp", "h2"], "grpc-exp,h2"),
                             (["h2"], "h2")):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(alpns)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(*cf)
            try:
                s = ctx.wrap_socket(socket.create_connection(
                    ("pes22-game.cs.konami.net", 443), timeout=15),
                    server_hostname="pes22-game.cs.konami.net")
                print(f"  {label:22s} -> alpn={s.selected_alpn_protocol()} "
                      f"tls={s.version()} cipher={s.cipher()[0]}", flush=True)
                s.close()
            except Exception as e:
                print(f"  {label:22s} ERR {type(e).__name__}: {e}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
