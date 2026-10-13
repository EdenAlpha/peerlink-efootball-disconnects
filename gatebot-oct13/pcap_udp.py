#!/usr/bin/env python3
"""Where did the match UDP actually go -- P2P (a peer IP) or relay (the
Google Cloud gamerelay address the gate handed out)?

Pure-stdlib pcap parser.  Tallies UDP packets+bytes by remote endpoint and
prints the top talkers, flagging the known relay addrs.
"""
import struct
import sys
from collections import defaultdict

PCAP = (r"C:\Users\Administrator\Documents\Default Project"
        r"\work\cap\game-final.pcap")
RELAY = {"34.163.149.29", "34.163.163.69"}   # gamerelay ip_addr from the gate


def ip4(b):
    return ".".join(str(x) for x in b)


def main():
    with open(PCAP, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            print("truncated header")
            return 1
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            end = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            end = ">"
        else:
            print("not a classic pcap (magic=%r) -- pcapng?" % magic)
            return 1
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        print("linktype=%d (1=ethernet,113=linux-cooked,0=null/loopback)"
              % linktype)

        udp = defaultdict(lambda: [0, 0])          # endpoint -> [pkts, bytes]
        tcp_hosts = defaultdict(int)
        protos = defaultdict(int)
        total = 0
        others = 0
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(end + "IIII", ph)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            total += 1
            # strip link layer
            if linktype == 1:                       # ethernet
                if len(data) < 14:
                    others += 1
                    continue
                ethertype = struct.unpack("!H", data[12:14])[0]
                off = 14
                if ethertype == 0x8100:             # VLAN tag
                    ethertype = struct.unpack("!H", data[16:18])[0]
                    off = 18
                if ethertype != 0x0800:             # only IPv4
                    others += 1
                    continue
            elif linktype == 113:                   # linux cooked
                if len(data) < 16:
                    others += 1
                    continue
                ethertype = struct.unpack("!H", data[14:16])[0]
                off = 16
                if ethertype != 0x0800:
                    others += 1
                    continue
            elif linktype == 0:                     # null/loopback
                if len(data) < 4:
                    others += 1
                    continue
                fam = struct.unpack(end + "I", data[:4])[0]
                off = 4
                if fam not in (2, 24, 28, 30):       # AF_INET variants
                    others += 1
                    continue
            elif linktype == 276:                   # Linux SLL2 (cooked v2)
                if len(data) < 20:
                    others += 1
                    continue
                ethertype = struct.unpack("!H", data[0:2])[0]
                off = 20
                if ethertype != 0x0800:
                    others += 1
                    continue
            else:
                print("unsupported linktype %d" % linktype)
                return 1

            # IPv4 header
            if len(data) < off + 20:
                others += 1
                continue
            vihl = data[off]
            if vihl >> 4 != 4:
                others += 1
                continue
            ihl = (vihl & 0xF) * 4
            proto = data[off + 9]
            src = ip4(data[off + 12:off + 16])
            dst = ip4(data[off + 16:off + 20])
            l4 = off + ihl
            if proto == 17 and len(data) >= l4 + 8:  # UDP
                sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
                plen = struct.unpack("!H", data[l4 + 4:l4 + 6])[0]
                # count BOTH directions keyed by the lower-port side's peer:
                # report every (ip,port) seen as a source or dest
                for side, (ip_, port_) in ((src, (src, sport)),
                                           (dst, (dst, dport))):
                    e = udp[(ip_, port_)]
                    e[0] += 1
                    e[1] += plen
                protos[proto] += 1
            else:
                protos[proto] += 1
            if proto == 6:
                tcp_hosts[dst] += 1

    print("\npackets parsed: %d (non-ipv4/other: %d)" % (total, others))
    print("\n=== PROTOCOL HISTOGRAM ===")
    PN = {6: "TCP", 17: "UDP", 1: "ICMP"}
    for p, c in sorted(protos.items(), key=lambda kv: -kv[1]):
        print("  %-5s proto=%-3d pkts=%d" % (PN.get(p, "?"), p, c))
    print("\n=== TOP UDP ENDPOINTS (by packets) ===")
    for (ip, port), (pkts, byt) in sorted(udp.items(),
                                          key=lambda kv: -kv[1][0])[:20]:
        tag = "  <== RELAY (google cloud)" if ip in RELAY else ""
        print("  %s:%-6d  pkts=%-7d bytes=%-10d%s"
              % (ip, port, pkts, byt, tag))

    relay_pkts = sum(v[0] for k, v in udp.items() if k[0] in RELAY)
    peer_pkts = sum(v[0] for k, v in udp.items() if k[0] not in RELAY)
    print("\n=== VERDICT ===")
    print("  UDP to relay addrs : %d packets" % relay_pkts)
    print("  UDP to other (p2p) : %d packets" % peer_pkts)
    if relay_pkts and not peer_pkts:
        print("  -> PLAYED OVER RELAY (no direct peer traffic)")
    elif peer_pkts and not relay_pkts:
        print("  -> PLAYED P2P (direct peer traffic, relay unused)")
    elif relay_pkts and peer_pkts:
        print("  -> MIXED / fallback (relay present + peer present)")
    else:
        print("  -> no UDP gameplay found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
