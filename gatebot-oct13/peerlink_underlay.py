#!/usr/bin/env python3
"""peerlink_underlay.py -- where does the PeerLink tunnel actually go on the wire?

udp_trace shows the tunnel is STUN-classified and both peers sustain ~30 pps.
This parses passthrough_capture.csv (full-packet internet side) to answer the
ONE question that decides how the server knows: is the tunnel relayed through a
Konami server (TURN/relay -> server sees the heartbeat) or direct P2P after a
STUN punch (server not in path)?

Read-only.  python peerlink_underlay.py
"""
import os
from collections import Counter

CAP = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\captures\match-2026-09-26")
Z = ("z1-tiamant-client", "z2-elijah-hotspot-owner")

STUN_TYPE = {0x0001: "ALLOC request", 0x0101: "ALLOC success",
             0x0003: "BIND request", 0x0101b: "", 0x0103: "BIND error",
             0x0017: "SEND/DATA indication", 0x0016: "CREATE-PERM req",
             0x0116: "CREATE-PERM ok", 0x0012: "REFRESH req",
             0x0112: "REFRESH ok"}
ATTR = {0x0001: "MAPPED-ADDR", 0x0006: "USERNAME", 0x0008: "REALM",
        0x0009: "NONCE", 0x000c: "XOR-PEER-ADDR", 0x0016: "XOR-RELAY-ADDR",
        0x0015: "DATA", 0x0020: "XOR-MAPPED-ADDR", 0x0014: "REALM?"}


def parse_stun(udp):
    if len(udp) < 20 or udp[4:8] != b"\x21\x12\xa4\x42":
        return None
    mt = int.from_bytes(udp[0:2], "big")
    ln = int.from_bytes(udp[2:4], "big")
    attrs = []
    i = 20
    while i + 4 <= len(udp) and len(attrs) < 8:
        at = int.from_bytes(udp[i:i + 2], "big")
        al = int.from_bytes(udp[i + 2:i + 4], "big")
        av = udp[i + 4:i + 4 + al]
        attrs.append((at, al, av))
        i += 4 + ((al + 3) & ~3)
    return mt, ln, attrs


def ip_str(b):
    return ".".join(str(x) for x in b)


for z in Z:
    print("=" * 78)
    print(z)
    print("=" * 78)
    pp = os.path.join(CAP, z, "passthrough_capture.csv")
    protos = Counter()
    dsts = Counter()
    stun_types = Counter()
    stun_peers = []            # (dst,dport, xor_peer) from SEND/DATA indications
    relay_addrs = Counter()
    udp_to = Counter()
    n = 0
    with open(pp, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or line.startswith("ts_ms,") \
                    or not line.strip():
                continue
            p = line.rstrip("\n").split(",")
            if len(p) < 9:
                continue
            n += 1
            ts, d, proto, src, sp, dst, dp, iplen, hx = p[0], p[1], p[2], \
                p[3], p[4], p[5], p[6], p[7], p[8]
            protos[proto] += 1
            dsts[(dst, dp)] += 1
            if proto == "udp":
                udp_to[(dst, dp)] += 1
                try:
                    b = bytes.fromhex(hx)
                except ValueError:
                    continue
                ihl = (b[0] & 0xF) * 4
                udp = b[ihl + 8:]
                s = parse_stun(udp)
                if s:
                    mt, ln, attrs = s
                    stun_types[mt] += 1
                    peer = None
                    relay = None
                    for (at, al, av) in attrs:
                        if at == 0x000c and al >= 8:      # XOR-PEER-ADDR
                            fam = av[1]
                            port = int.from_bytes(av[2:4], "big") ^ \
                                (0x2112 >> 8 | (0x2112 & 0xff) << 8)
                            port = int.from_bytes(av[2:4], "big") ^ \
                                (0x2112A442 >> 16)
                            if fam == 1 and len(av) >= 8:
                                xorip = bytes(x ^ y for x, y in
                                              zip(av[4:8],
                                                  bytes.fromhex("2112a442")))
                                peer = "%s:%d" % (ip_str(xorip), port)
                        if at == 0x0016 and al >= 8:      # XOR-RELAY-ADDR
                            if av[1] == 1 and len(av) >= 8:
                                xorip = bytes(x ^ y for x, y in
                                              zip(av[4:8],
                                                  bytes.fromhex("2112a442")))
                                rport = int.from_bytes(av[2:4], "big") ^ \
                                    (0x2112A442 >> 16)
                                relay = "%s:%d" % (ip_str(xorip), rport)
                    if relay:
                        relay_addrs[relay] += 1
                    if peer:
                        stun_peers.append((dst, dp, mt, peer))
    print("  rows=%d protos=%s" % (n, dict(protos)))
    print("  -- top udp destinations --")
    for (d, dp), c in udp_to.most_common(12):
        print("     %6d  %s:%s" % (c, d, dp))
    print("  -- STUN message types --")
    for mt, c in stun_types.most_common():
        print("     %6d  0x%04x %s" % (c, mt, STUN_TYPE.get(mt, "")))
    print("  -- XOR-RELAY-ADDR (TURN relay = server in path) --")
    for r, c in relay_addrs.most_common(6):
        print("     %6d  %s" % (c, r))
    print("  -- SEND/DATA indications w/ XOR-PEER-ADDR (first 8) --")
    for (dst, dp, mt, peer) in stun_peers[:8]:
        print("     %s:%s type=0x%04x peer=%s" % (dst, dp, mt, peer))
    print()
