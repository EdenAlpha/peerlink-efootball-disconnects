#!/usr/bin/env python3
"""relay_flows.py -- what does phone-to-internet game traffic look like?

The user tunnels P2P phone-to-phone traffic over WiFi and needs to know
whether a Konami relay (SC) can go through the same tunnel: what transport
and encryption the relay uses, and whether anything binds it to the client
IP (which tunneling would change).

This capture is the internet side (non-game) traffic, so phone->Konami
relay traffic IS in here if the match used one.  List every flow with its
protocol fingerprint from first payload bytes.

  python relay_flows.py
"""
import struct
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
       r"\captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv")


def fingerprint(payload):
    if len(payload) < 4:
        return "tiny<%d>" % len(payload)
    b0 = payload[0]
    if payload[:2] == b"\x16\x03" and len(payload) >= 6:
        return "TLS handshake (0x16 0x03) len~%d" % struct.unpack(
            "!H", payload[3:5])[0]
    if b0 in (20, 21, 22, 23, 25) and len(payload) >= 13 and \
            payload[1:3] in (b"\xfe\xff", b"\xfe\xfd"):
        return {20: "DTLS-ccs?", 21: "DTLS-alert", 22: "DTLS-handshake",
                23: "DTLS-appdata", 25: "DTLS-heartbeat"}.get(b0, "?")
    if len(payload) >= 20 and payload[4:8] == b"\x21\x12\xa4\x42":
        mt = struct.unpack("!H", payload[:2])[0]
        return {0x0001: "STUN-BindingReq", 0x0101: "STUN-BindingResp",
                0x0003: "TURN-AllocateReq", 0x0103: "TURN-AllocateResp",
                0x0115: "STUN-401?", 0x0114: "STUN-err?"}.get(
                    mt, "STUN/0x%04x" % mt)
    if payload[:4] == b"GET " or payload[:5] == b"POST ":
        return "HTTP " + payload.split(b"\r\n", 1)[0][:40].decode(
            "latin-1", "replace")
    if payload[:2] == b"\x45\x00" or payload[:1] == b"\x45":
        return "inner-IP?"
    return "opaque 0x%02x len=%d head=%s" % (b0, len(payload),
                                            payload[:8].hex())


def main() -> int:
    flows = defaultdict(lambda: {"n": 0, "bytes": 0, "first": None,
                                 "sizes": defaultdict(int)})
    events = 0
    with open(CAP, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                if line.startswith("# event"):
                    events += 1
                continue
            parts = line.split(",")
            if len(parts) < 9 or parts[0] == "ts_ms":
                continue
            try:
                _ts, direction, proto, src, sport, dst, dport, _l, hexp = \
                    parts[:9]
                payload = bytes.fromhex(hexp)
                sport, dport = int(sport), int(dport)
            except ValueError:
                continue
            if len(payload) < 28 or (payload[0] >> 4) != 4:
                continue
            ihl = (payload[0] & 0xF) * 4
            if proto == "tcp" and len(payload) >= ihl + 13:
                body = payload[ihl + ((payload[ihl + 12] >> 4) * 4):]
            else:
                body = payload[ihl + 8:]
            key = (proto, dst, dport)
            fl = flows[key]
            fl["n"] += 1
            fl["bytes"] += len(payload)
            fl["sizes"][len(body)] += 1
            if fl["first"] is None and direction == "t" and body:
                fl["first"] = (src, sport, bytes(body[:32]))
            if direction == "t":
                fl["src"] = (src, sport)

    print("event lines: %d   flows: %d\n" % (events, len(flows)))
    print("=== phone->internet flows (t) with a first payload ===")
    for (proto, dst, dport), fl in sorted(
            flows.items(), key=lambda kv: -kv[1]["n"]):
        if fl["first"] is None:
            continue
        src, sport, head = fl["first"]
        print("%-3s %-16s:%-6d pkts=%-6d bytes=%-8d from %s:%s" % (
            proto.upper(), dst, dport, fl["n"], fl["bytes"], src, sport))
        print("     first: %s" % fingerprint(head))
        top = sorted(fl["sizes"].items(), key=lambda kv: -kv[1])[:6]
        print("     body sizes: %s" % ", ".join(
            "%d(x%d)" % (s, c) for s, c in top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
