#!/usr/bin/env python3
"""turn_rendezvous.py -- the TURN server tells us the DTLS rendezvous.

Discovery chain (worked out 2026-10-13):

  CMD_GET_TURN_SERVER_LIST {"turn_account_param":"","turn_time_limit":0}
      -> turn_server_list  132.8.211.130.bc.googleusercontent.com:443
      -> turn_account      origin turns://pes20.turn.konami.com:5349
  TCP+TLS 443 (not 5349) + STUN Allocate
      -> 401 Unauthorized, NONCE, REALM ''
      -> SOFTWARE (60 B) = "34.182.219.64:30317,64.219.182.34.bc.goo..."

SOFTWARE is NOT a software string.  It is the rendezvous address list in
exactly the compound form CMD_GET_GAME_SESSION uses for gamerelay.ip_addr.
That matches POSTROOM_FLOW.md:1814 -- "the rendezvous IPs resolve from
*.bc.googleusercontent.com ... chain3 CAN discover the rendezvous endpoint
the same way the real client does; it just never does."

This script pulls it live and replays the capture's byte-exact DTLS
ClientHello (195 B, DTLS 1.0 cookie probe) at whatever it names.

  python turn_rendezvous.py
  python turn_rendezvous.py --allocate   also attempt a full TURN allocation
"""
import socket
import ssl
import struct
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
import replay_clienthello as R                                     # noqa: E402

TURN_HOST = "130.211.8.132"
TURN_PORT = 443
SNI = "pes20.turn.konami.com"
TXID = bytes.fromhex("0a0b0c0d0e0f101112131415")

ATTR = {0x0006: "USERNAME", 0x0014: "REALM", 0x0015: "NONCE",
        0x0009: "ERROR-CODE", 0x000A: "UNKNOWN-ATTRS", 0x000D: "LIFETIME",
        0x0020: "XOR-RELAYED-ADDR", 0x0016: "XOR-PEER-ADDR",
        0x0008: "MESSAGE-INTEGRITY", 0x0019: "FINGERPRINT",
        0x8022: "SOFTWARE", 0x0011: "REQUESTED-TRANSPORT",
        0x0024: "REALM-BYTES"}


def tls_socket():
    raw = socket.create_connection((TURN_HOST, TURN_PORT), timeout=6)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(raw, server_hostname=SNI)
    ss.settimeout(6)
    return ss


def parse_stun(d):
    out = []
    if len(d) < 20:
        return out
    mt, ml = struct.unpack("!HH", d[:4])
    i = 20
    while i + 4 <= min(20 + ml, len(d)):
        at, al = struct.unpack("!HH", d[i:i + 4])
        v = d[i + 4:i + 4 + al]
        name = ATTR.get(at, "0x%04x" % at)
        if at == 0x0009 and len(v) >= 4:
            code = struct.unpack("!I", v[:4])[0] & 0xFF
            cls = (struct.unpack("!I", v[:4])[0] >> 16) & 0x7
            txt = v[4:].decode("utf-8", "replace")
            out.append((name, "[%d%03d] %s" % (cls, code, txt), v))
        elif at in (0x0014, 0x0015, 0x0006, 0x8022):
            out.append((name, v.decode("utf-8", "replace"), v))
        elif at == 0x000A:
            out.append((name, [hex(struct.unpack("!H", v[j:j + 2])[0])
                               for j in range(0, len(v) - 1, 2)], v))
        else:
            out.append((name, "%dB" % len(v), v))
        i += 4 + al + (4 - (al % 4)) % 4
    return mt, out


def allocate():
    ss = tls_socket()
    ss.sendall(struct.pack("!HHI", 0x0003, 0, 0x2112A442) + TXID)
    d = ss.recv(4096)
    ss.close()
    mt, at = parse_stun(d)
    return mt, at


def main() -> int:
    print("=== STUN Allocate over TLS to %s:%d ===" % (TURN_HOST, TURN_PORT))
    mt, at = allocate()
    print("  method=0x%04x" % mt)
    soft = nonce = realm = ""
    for name, val, _raw in at:
        print("  %-18s %s" % (name, val if len(str(val)) < 300 else str(val)[:300]))
        if name == "SOFTWARE":
            soft = val
        elif name == "NONCE":
            nonce = val
        elif name == "REALM":
            realm = val

    if not soft:
        print("  no SOFTWARE attribute -> no rendezvous to dial")
        return 1

    print("\n=== rendezvous list from SOFTWARE (%d chars) ===" % len(soft))
    print("  %s" % soft)
    cands = []
    last_port = None
    for part in soft.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            host, _, port = part.rpartition(":")
            if port.isdigit():
                cands.append((host, int(port)))
                last_port = int(port)
                continue
        if part.isdigit():
            # trailing flag (e.g. ",0"), not an address
            continue
        # bare hostname: same rendezvous, so reuse the port just issued
        if last_port:
            cands.append((part, last_port))
    for h, p in cands:
        print("    %-56s %s" % (h, p if p else "(resolve only)"))

    # the capture's byte-exact first flight
    probe = None
    for key, pkts in R.load_capture().items():
        dport = key[3]
        if not (30000 <= dport <= 33000):
            continue
        for d, pl in pkts:
            if d == "t" and pl[:1] == b"\x16":
                probe = pl
                break
        if probe:
            break
    print("\nprobe: %s (%dB)" % (R.describe(probe), len(probe)) if probe
          else "\nprobe: none found")

    print("\n=== DTLS probe of the issued rendezvous ===")
    for host, port in cands:
        if probe and port:
            try:
                ip = socket.getaddrinfo(host, port, socket.AF_INET,
                                        socket.SOCK_DGRAM)[0][4][0]
            except OSError as e:
                print("  %-52s dns %s" % (host, e))
                continue
            print("  %-52s %-6d %s"
                  % (host, port, R.send(ip, port, probe, timeout=5.0)))
        else:
            try:
                print("  %-52s -> %s" % (host, socket.gethostbyname(host)))
            except OSError as e:
                print("  %-52s dns %s" % (host, e))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
