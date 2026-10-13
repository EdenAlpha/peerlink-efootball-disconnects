#!/usr/bin/env python3
"""probe_turn2.py -- characterise the P2P TURN/DTLS rendezvous returned by
CMD_GET_TURN_SERVER_LIST.

probe_turnlist.py proved the command answers NOERR with a single endpoint
(132.8.211.130.bc.googleusercontent.com:443) but a hand-rolled DTLS
ClientHello got no reply.  Before building a real DTLS stack we need to know
WHAT listens there:

  tcp443   plain TCP connect + TLS ClientHello   (turns://  is TCP TLS)
  udp443   STUN binding request                  (TURN is STUN-based)
  udp443   real DTLS 1.0 cookie probe (0xfeff)    (client's first flight,
                                                   byte shape from the
                                                   2026-09-26 capture)
  udp443   real DTLS 1.2 ClientHello (0xfefd)

Credentials from turn_account are session-bound; this script never prints
them, it only prints reachability.
"""
import json
import socket
import struct
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import Gate, load_capture, login, PACE, describe       # noqa: E402

DTLS_COOKIE_PROBE = None   # filled from the capture if available


def turn_list(g):
    m = g.envelope("CMD_GET_TURN_SERVER_LIST")
    m["turn_account_param"] = ""
    m["turn_time_limit"] = 0
    return g.send(m, timeout=15)


def stun_binding(txid=None):
    """A minimal but structurally valid STUN Binding Request over UDP."""
    txid = txid or bytes.fromhex("0102030405060708090a0b0c")
    # MESSAGE-BINDING request = 0x0001, length 0, magic cookie, txid
    head = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txid
    # fingerprint-ish padding not required for a binding request
    return head


def dtls_clienthello(version=0xFEFD, epoch=0, seq=0):
    """Build a plausible DTLS 1.2 ClientHello.

    Not cryptographically exact -- we only care whether SOMETHING answers.
    Cookie empty, one cipher (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, which
    the 2026-09-26 capture shows) + a couple of common ECDHE suites,
    supported_groups secp256r1, ec_point_formats uncompressed, SNI absent.
    """
    rnd = bytes(range(0x20, 0x60))
    suites = struct.pack("!HHHHHH", 0xC02B, 0xC02F, 0xC02C,
                         0xC030, 0xC013, 0xC014)
    # DTLS extensions each carry their own 2-byte type + 2-byte data length.
    curves = struct.pack("!HH", 10, 4) + struct.pack("!HH", 0x0017, 0x0018)
    ptfmt = struct.pack("!HH", 11, 2) + b"\x01\x00"
    sigs = struct.pack("!HH", 13, 4) + struct.pack("!HH", 0x0403, 0x0503)
    ext = curves + ptfmt + sigs

    body = (struct.pack("!H", version)     # client_version
            + rnd                          # random (32)
            + b"\x00"                      # session_id length 0
            + b"\x00"                      # cookie length 0  (DTLS-only field)
            + struct.pack("!H", len(suites)) + suites
            + b"\x01\x00"                  # compression: 1 method, null
            + struct.pack("!H", len(ext)) + ext)
    hs = (b"\x01" + len(body).to_bytes(3, "big")            # client_hello
          + struct.pack("!H", 0) + b"\x00" * 6              # message_seq 0
          + b"\x00\x00\x00" + len(body).to_bytes(3, "big")  # frag offset/len
          + body)
    # DTLS record header: type(1) ver(2) epoch(2) seq(6) length(2)
    return (b"\x16" + struct.pack("!H", version)
            + struct.pack("!H", epoch) + b"\x00" * 6
            + struct.pack("!H", len(hs)) + hs)


def udp_probe(ip, port, payload, timeout, label):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(payload, (ip, port))
        try:
            d, frm = s.recvfrom(4096)
        except socket.timeout:
            return "%-18s timeout (%.0fs)" % (label, timeout)
        ms = int((time.time() - t0) * 1000)
        if d[:1] == b"\x16" and len(d) > 13:
            return "%-18s ANSWERED DTLS hs=%d %dB %dms from %s:%d" % (
                label, d[13], len(d), ms, frm[0], frm[1])
        if d[:2] == b"\x01\x01" or (len(d) >= 20 and d[:2] == b"\x01\x01"):
            return "%-18s ANSWERED STUN-binding-response %dB %dms" % (
                label, len(d), ms)
        return "%-18s ANSWERED %dB %dms head=%s" % (
            label, len(d), ms, d[:16].hex())
    except OSError as e:
        return "%-18s err %s" % (label, e)
    finally:
        s.close()


def tcp_probe(ip, port, timeout=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
        ms = int((time.time() - t0) * 1000)
    except OSError as e:
        return "tcp443             err %s" % e
    finally:
        pass
    try:
        # TLS ClientHello probe: does a TLS listener answer?
        ch = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x00\x2f"
              + b"\x01\x00" + b"\x00\x00")
        rec = b"\x16\x03\x01" + struct.pack("!H", len(ch)) + ch
        s.sendall(rec)
        try:
            d = s.recv(1024)
        except socket.timeout:
            return "tcp443             connected %dms, no TLS reply" % ms
        if d[:1] == b"\x16":
            return "tcp443             connected %dms, TLS ServerHello/Alert %dB" % (
                ms, len(d))
        return "tcp443             connected %dms, %dB %s" % (
            ms, len(d), d[:16].hex())
    except OSError as e:
        return "tcp443             connected %dms, io err %s" % (ms, e)
    finally:
        s.close()


def main() -> int:
    reqs, _ = load_capture()
    g = Gate()
    ok, r = login(g, reqs)
    print("login -> %s" % (r.get("result") if ok else describe(r)))
    if not ok:
        return 1
    time.sleep(PACE)

    tr = turn_list(g)
    print("GET_TURN_SERVER_LIST -> %s" % tr.get("result"))
    tsl = tr.get("turn_server_list") or []
    if not tsl:
        print("  no turn_server_list")
        return 1

    for e in tsl:
        host, port = e.get("address"), e.get("tls_port") or e.get("port")
        print("\n=== %s:%s (zone %s) ===" % (host, port, e.get("zone")))
        try:
            ip = socket.getaddrinfo(host, port, socket.AF_INET,
                                    socket.SOCK_DGRAM)[0][4][0]
        except OSError as ex:
            print("  dns: %s" % ex)
            continue
        print("  -> %s" % ip)
        print("  %s" % tcp_probe(ip, port))
        for label, payload in (
                ("stun-binding", stun_binding()),
                ("dtls12-hello", dtls_clienthello()),
                ("dtls10-probe", dtls_clienthello(0xFEFF)),
        ):
            print("  %s" % udp_probe(ip, port, payload, 3.0, label))

        # a second pass with a longer wait, in case of slow first reply
        print("  %s" % udp_probe(ip, port, stun_binding(), 8.0, "stun-slow"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
