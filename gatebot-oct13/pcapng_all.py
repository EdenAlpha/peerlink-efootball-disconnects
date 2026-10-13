#!/usr/bin/env python3
"""pcapng_all.py -- census EVERYTHING in the tunnel pcapng, including skipped."""
import struct
import sys
from collections import Counter

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from pcapng_read import read_pcapng                                  # noqa: E402

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"


def main() -> int:
    m = sys.argv[1] if len(sys.argv) > 1 else "m5"
    pkts = read_pcapng(D + "\\%s\\tunnel_capture.pcapng" % m)
    print("%s raw packets: %d" % (m, len(pkts)))
    kinds = Counter()
    ports = Counter()
    non_udp = []
    for pkt in pkts:
        if len(pkt) < 14:
            kinds["runt<%d>" % len(pkt)] += 1
            continue
        if pkt[12:14] == b"\x08\x00":
            ip = pkt[14:]
        elif (pkt[0] >> 4) == 4:
            kinds["raw-ip-no-eth"] += 1
            ip = pkt
        elif (pkt[0] >> 4) == 6:
            kinds["ipv6"] += 1
            continue
        else:
            kinds["non-ip eth=0x%s" % pkt[12:14].hex()] += 1
            continue
        if len(ip) < 20:
            kinds["short-ip"] += 1
            continue
        proto = ip[9]
        if proto != 17:
            kinds["ip-proto-%d" % proto] += 1
            if len(non_udp) < 5:
                non_udp.append((proto, len(ip), ip[:40].hex()))
            continue
        ihl = (ip[0] & 0xF) * 4
        if len(ip) < ihl + 8:
            kinds["short-udp"] += 1
            continue
        sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        kinds["udp"] += 1
        ports[(src, sport, dst, dport)] += 1
    print("kinds:", dict(sorted(kinds.items())))
    print("top udp flows:")
    for k, c in ports.most_common(15):
        print("  %6d  %s:%s -> %s:%s" % (c, k[0], k[1], k[2], k[3]))
    for proto, L, h in non_udp:
        print("  non-udp proto=%d len=%d %s" % (proto, L, h[:80]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
