#!/usr/bin/env python3
"""dump_turn401.py -- show the raw STUN Allocate challenge, byte for byte.

Every credential scheme tried in probe_turn_auth.py came back 401, so the
assumptions baked into the parser are now suspect rather than the keys.  In
particular REALM prints as the empty string, which would be unusual for a
TURN server -- if its length or bytes are being misread, every MD5(u:realm:p)
key derived from it is wrong by construction.

  python dump_turn401.py
"""
import socket
import ssl
import struct
import sys

TURN_HOST, TURN_PORT, SNI = "130.211.8.132", 443, "pes20.turn.konami.com"
MAGIC = 0x2112A442
NAMES = {0x0006: "USERNAME", 0x0014: "REALM", 0x0015: "NONCE",
         0x0009: "ERROR-CODE", 0x000A: "UNKNOWN-ATTRS", 0x000D: "LIFETIME",
         0x0020: "XOR-RELAYED-ADDR", 0x0016: "XOR-PEER-ADDR",
         0x0008: "MESSAGE-INTEGRITY", 0x0019: "FINGERPRINT",
         0x8022: "SOFTWARE", 0x0011: "REQUESTED-TRANSPORT",
         0x8028: "GOOGLE-SESSION-INFO", 0x0012: "PEER-ADDRESS",
         0x0024: "REALM2", 0x8030: "DATA"}


def main() -> int:
    raw = socket.create_connection((TURN_HOST, TURN_PORT), timeout=6)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(raw, server_hostname=SNI)
    ss.settimeout(6)

    txid = bytes.fromhex("0102030405060708090a0b0c")
    msg = struct.pack("!HHI", 0x0003, 0, MAGIC) + txid
    ss.sendall(msg)
    d = ss.recv(4096)
    ss.close()

    print("=== request (%d B) ===" % len(msg))
    print("  " + msg.hex())

    print("\n=== response (%d B) ===" % len(d))
    print("  " + d.hex())
    mt, ml = struct.unpack("!HH", d[:4])
    rtxid = d[4:20]
    print("\n  method/class : 0x%04x  (0x0113 = Allocate error response)" % mt)
    print("  length       : %d   (header says %d, datagram is %d)"
          % (len(d) - 20, ml, len(d)))
    print("  txid echoed  : %s  match=%s"
          % (rtxid.hex(), rtxid == txid))
    print("  magic        : %s  ok=%s"
          % (d[4:8].hex(), d[4:8] == struct.pack("!I", MAGIC)))

    i = 20
    print("\n  attributes:")
    while i + 4 <= len(d):
        at, al = struct.unpack("!HH", d[i:i + 4])
        v = d[i + 4:i + 4 + al]
        pad = (4 - al % 4) % 4
        nm = NAMES.get(at, "0x%04x" % at)
        print("    %-22s type=0x%04x len=%-3d %s"
              % (nm, at, al, render(nm, v)))
        if at == 0x0009 and len(v) >= 4:
            print("        raw error word: %s  -> class=%d number=%d"
                  % (v[:4].hex(),
                     (struct.unpack("!I", v[:4])[0] >> 8) & 0x7,
                     struct.unpack("!I", v[:4])[0] & 0xFF))
        i += 4 + al + pad
    return 0


def render(nm, v):
    if nm in ("NONCE", "USERNAME", "SOFTWARE"):
        return repr(v.decode("utf-8", "replace"))
    if nm == "REALM":
        return "len=%d bytes=%s repr=%r" % (len(v), v.hex(),
                                            v.decode("utf-8", "replace"))
    if nm == "MESSAGE-INTEGRITY" or nm == "FINGERPRINT":
        return v.hex()
    return "%dB" % len(v)


if __name__ == "__main__":
    raise SystemExit(main())
