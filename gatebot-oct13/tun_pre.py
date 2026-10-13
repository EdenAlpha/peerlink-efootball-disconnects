#!/usr/bin/env python3
"""tun_pre.py -- pre-kickoff big packets from the m5 underlay pcapng.

m5's pcapng (22,909 pkts) should span the whole session like m1/m3's traces
(~30k rows, ~9.8k pre-kickoff).  Dump the first big (>=300B) packets in
capture order with full hex: are they DTLS? key exchange? plaintext?
"""
import struct
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from pcapng_read import read_pcapng, fp                            # noqa: E402

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"


def main() -> int:
    pkts = read_pcapng(D + r"\m5\tunnel_capture.pcapng")
    print("m5 pcapng packets: %d" % len(pkts))
    inner = []
    for pkt in pkts:
        if len(pkt) < 42:
            continue
        ip = pkt[14:] if pkt[12:14] == b"\x08\x00" else pkt
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        inner.append((src, sport, dst, dport, ip[ihl + 8:]))

    print("inner UDP packets: %d" % len(inner))
    # direction census
    from collections import Counter
    dc = Counter((s, d) for s, _, d, _, _ in inner)
    print("direction:", dict(dc))

    print("\n=== big packets (>=300B) in capture order (first 25) ===")
    shown = 0
    for i, (src, sport, dst, dport, b) in enumerate(inner):
        if len(b) >= 300 and shown < 25:
            shown += 1
            print("#%d %s:%s -> %s:%s %dB [%s]" % (
                i, src, sport, dst, dport, len(b), fp(b)))
    # full hex of the first three big ones
    n = 0
    for i, (src, sport, dst, dport, b) in enumerate(inner):
        if len(b) >= 300 and n < 3:
            n += 1
            print("\n--- #%d %dB first-128 ---" % (i, len(b)))
            h = b[:128].hex()
            for j in range(0, len(h), 64):
                print("  " + h[j:j + 64])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
