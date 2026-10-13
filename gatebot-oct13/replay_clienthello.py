#!/usr/bin/env python3
"""replay_clienthello.py -- take the REAL DTLS bytes out of the 2026-09-26
capture and replay them at live candidates.

Why this matters: hand-built ClientHellos get silently dropped by picky DTLS
stacks.  The capture contains the phone's exact first flight (195 bytes,
DTLS 1.0 0xfeff, handshake type 1) and the server's exact answers -- so we
can (a) learn the real handshake progression, and (b) replay byte-identical
probes instead of guesses.

Also dumps the server-side records so we see what a successful exchange looks
like (hello_verify / server_hello / appdata sizes).

  python replay_clienthello.py --dump            show the capture's records
  python replay_clienthello.py --replay          replay at all candidates
"""
import csv
import collections
import socket
import struct
import sys
import time

CAP = (r"C:\Users\Administrator\Documents\Default Project\peerlink-"
       r"efootball-disconnects\captures\match-2026-09-26"
       + "\\z1-tiamant-client\\passthrough_capture.csv")

# Session relay endpoints read from block 102 of the 2026-10-12 gate capture
# (gamerelay.ip_addr compound + token), port field = 1.
RELAY = [
    ("29.149.163.34.bc.googleusercontent.com", 5735),
    ("69.38.163.34.bc.googleusercontent.com", 5736),
    ("69.38.163.34.bc.googleusercontent.com", 443),
]
# TURN rendezvous from CMD_GET_TURN_SERVER_LIST (live, this session).
TURN = [("132.8.211.130.bc.googleusercontent.com", 443),
        ("132.8.211.130.bc.googleusercontent.com", 5349)]
# The 30xxx flows a real match used (2026-09-26).
P30 = [("34.156.177.234", 30236), ("34.156.177.234", 30116),
       ("104.199.46.171", 30222), ("34.22.210.195", 30650),
       ("34.38.190.21", 30905)]

HSN = {0: "hello_request", 1: "client_hello", 2: "server_hello",
       3: "hello_verify", 4: "new_session_ticket", 11: "certificate",
       12: "server_key_exchange", 13: "certificate_request",
       14: "server_hello_done", 15: "certificate_verify", 16: "client_key_x",
       20: "finished"}
RTN = {0x14: "ccs", 0x15: "alert", 0x16: "handshake", 0x17: "appdata"}


def udp_body(raw_hex):
    try:
        b = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    if not b:
        return None
    if b[0] >> 4 == 4:
        ihl = (b[0] & 0x0F) * 4
        if len(b) < ihl + 8 or b[9] != 17:
            return None
        return b[ihl + 8:]
    if b[0] >> 4 == 6:
        if len(b) < 48 or b[6] != 17:
            return None
        return b[48:]
    return None


def records(p):
    """Yield (content_type, version, epoch, seq, body) from a DTLS stream."""
    out, i = [], 0
    while i + 13 <= len(p):
        ct, ver, ep = p[i], struct.unpack("!H", p[i + 1:i + 3])[0], \
            struct.unpack("!H", p[i + 3:i + 5])[0]
        seq = int.from_bytes(p[i + 5:i + 11], "big")
        ln = struct.unpack("!H", p[i + 11:i + 13])[0]
        body = p[i + 13:i + 13 + ln]
        if len(body) < ln:
            break
        out.append((ct, ver, ep, seq, body))
        i += 13 + ln
    return out


def describe(p):
    bits = []
    for ct, ver, ep, seq, body in records(p):
        if len(body) < 4:
            bits.append("%s ver=%04x len=%d" % (RTN.get(ct, ct), ver, len(body)))
            continue
        if ct == 0x16:
            hst, hln = body[0], int.from_bytes(body[1:4], "big")
            bits.append("HS %s ver=%04x ep=%d len=%d"
                        % (HSN.get(hst, "hs%d" % hst), ver, ep, len(body)))
        else:
            bits.append("%s ver=%04x ep=%d len=%d"
                        % (RTN.get(ct, ct), ver, ep, len(body)))
    return " + ".join(bits)


def load_capture():
    flows = collections.OrderedDict()
    with open(CAP, newline="", encoding="utf-8", errors="replace") as f:
        rows = csv.DictReader(ln for ln in f if not ln.startswith("#"))
        for row in rows:
            if row.get("proto", "").lower() != "udp":
                continue
            dst = row.get("dst") or ""
            dport = row.get("dport") or "0"
            if dst.startswith("10.0.0.") or dst.startswith("8.8."):
                continue          # skip DNS and the phone's own LAN
            p = udp_body(row.get("payload_hex") or "")
            if not p or len(p) < 13 or p[0] not in (0x14, 0x15, 0x16, 0x17):
                continue
            key = (row["src"], int(row["sport"]), dst, int(dport))
            flows.setdefault(key, []).append((row["dir"], p))
    return flows


def dump():
    flows = load_capture()
    print("=== DTLS flows in the capture (server-side and client-side) ===")
    for key, pkts in flows.items():
        ver = pkts[0][1][1:3]
        if struct.unpack("!H", ver)[0] not in (0xFEFF, 0xFEFD, 0x0100):
            continue
        print("\n%s:%d -> %s:%d   (%d packets)"
              % (key[0], key[1], key[2], key[3], len(pkts)))
        for i, (d, p) in enumerate(pkts[:14]):
            print("   %s %s" % (d, describe(p)))
        if len(pkts) > 14:
            print("   ... %d more" % (len(pkts) - 14))
    return flows


def replay(flows):
    # exact first flight per destination, taken from the capture
    probes = {}
    for key, pkts in flows.items():
        for d, p in pkts:
            if d == "t" and p[:1] == b"\x16":
                probes[(key[2], key[3])] = p
                break
    print("=== captured ClientHellos: %d distinct destinations ===" % len(probes))
    for k, v in probes.items():
        print("   %s:%-6d %dB  %s" % (k[0], k[1], len(v), describe(v)))

    targets = []
    for grp in (list(probes), RELAY, TURN, P30):
        for t in grp:
            if t not in targets:
                targets.append(t)
    print("\n=== replaying the capture's own bytes at %d candidates ==="
          % len(targets))
    for host, port in targets:
        try:
            ip = socket.getaddrinfo(host, port, socket.AF_INET,
                                    socket.SOCK_DGRAM)[0][4][0]
        except OSError as e:
            print("   %-46s %-6d dns %s" % (host, port, e))
            continue
        # the capture's own bytes first, then a fresh synthetic flight
        payloads = []
        if (host, port) in probes:
            payloads.append(("real", probes[(host, port)]))
        payloads.append(("synth", synth()))
        res = []
        for label, pl in payloads:
            res.append("%s=%s" % (label, send(ip, port, pl)))
        print("   %-46s %-6d %s" % (host, port, " | ".join(res)))


def synth():
    rnd = bytes(range(0x20, 0x60))
    suites = struct.pack("!HHHHHH", 0xC02B, 0xC02F, 0xC02C,
                         0xC030, 0xC013, 0xC014)
    curves = struct.pack("!HH", 10, 4) + struct.pack("!HH", 0x0017, 0x0018)
    ptfmt = struct.pack("!HH", 11, 2) + b"\x01\x00"
    sigs = struct.pack("!HH", 13, 4) + struct.pack("!HH", 0x0403, 0x0503)
    ext = curves + ptfmt + sigs
    body = (struct.pack("!H", 0xFEFF) + rnd + b"\x00" + b"\x00"
            + struct.pack("!H", len(suites)) + suites
            + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    hs = (b"\x01" + len(body).to_bytes(3, "big")
          + struct.pack("!H", 0) + b"\x00" * 6
          + b"\x00\x00\x00" + len(body).to_bytes(3, "big") + body)
    return (b"\x16" + b"\xfe\xff" + b"\x00\x00" + b"\x00" * 6
            + struct.pack("!H", len(hs)) + hs)


def send(ip, port, payload, timeout=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (ip, port))
        t0 = time.time()
        d, frm = s.recvfrom(4096)
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return "err %s" % e
    finally:
        s.close()
    return "ANSWERED %dB %dms from %s:%d  [%s]" % (
        len(d), int((time.time() - t0) * 1000), frm[0], frm[1], describe(d))


def main() -> int:
    if "--replay" in sys.argv:
        replay(dump())
    else:
        dump()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
