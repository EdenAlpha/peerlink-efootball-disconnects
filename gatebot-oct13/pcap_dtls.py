#!/usr/bin/env python3
"""pcap_dtls.py -- which DTLS endpoints did the REAL 2026-10-12 match use?

scans cap/game-final.pcap for UDP datagrams carrying DTLS records (content
type 0x14-0x17, version 0xfe??) and for STUN, groups them by conversation,
and prints the handshake types seen per endpoint.  This is the live ground
truth for where chain3 must open its DTLS session.

Read-only.  python pcap_dtls.py
"""
import struct
from collections import defaultdict

PCAP = r"C:\Users\Administrator\Documents\Default Project\work\cap\game-final.pcap"

HS = {0: "hello_request", 1: "client_hello", 2: "server_hello",
      3: "hello_verify_request", 11: "certificate", 12: "server_key_exchange",
      13: "certificate_request", 14: "server_hello_done",
      15: "certificate_verify", 16: "client_key_exchange", 20: "finished"}
CT = {20: "CCS", 21: "alert", 22: "handshake", 23: "appdata"}


def is_dtls(p):
    return (len(p) >= 13 and 0x14 <= p[0] <= 0x17
            and p[1] == 0xFE and p[2] in (0xFF, 0xFD, 0xFE))


def is_stun(p):
    return len(p) >= 20 and (p[0] & 0xFC) == 0 and p[4:8] == b"\x21\x12\xa4\x42"


def read_pcap(path):
    """yield (src, dst, sport, dport, payload) for every IPv4/UDP packet."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1" or magic == b"\x4d\x3c\xb2\xa1":
            endian, nano = "<", (magic == b"\x4d\x3c\xb2\xa1")
        elif magic == b"\xa1\xb2\xc3\xd4" or magic == b"\xa1\xb2\x3c\x4d":
            endian, nano = ">", (magic == b"\xa1\xb2\x3c\x4d")
        else:
            raise SystemExit("not a pcap: %r" % magic)
        link = struct.unpack_from(endian + "I", gh, 20)[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            _, _, caplen, _ = struct.unpack_from(endian + "IIII", ph, 0)
            buf = f.read(caplen)
            if len(buf) < caplen:
                return
            off = 0
            if link == 1:                     # ethernet
                if len(buf) < 14:
                    continue
                eth = struct.unpack_from(">H", buf, 12)[0]
                off = 14
                if eth == 0x8100:             # vlan
                    eth = struct.unpack_from(">H", buf, 16)[0]
                    off = 18
                if eth != 0x0800:
                    continue
            elif link == 101:                 # raw IP
                pass
            elif link == 113:                 # linux cooked (SLL)
                if len(buf) < 16 or struct.unpack_from(">H", buf, 14)[0] != 0x0800:
                    continue
                off = 16
            elif link == 276:                 # linux cooked v2 (SLL2)
                if len(buf) < 20 or struct.unpack_from(">H", buf, 0)[0] != 0x0800:
                    continue
                off = 20
            else:
                continue
            if len(buf) < off + 20 or buf[off] >> 4 != 4:
                continue
            ihl = (buf[off] & 0x0F) * 4
            if buf[off + 9] != 17:            # UDP only
                continue
            src = ".".join(str(x) for x in buf[off + 12:off + 16])
            dst = ".".join(str(x) for x in buf[off + 16:off + 20])
            u = off + ihl
            if len(buf) < u + 8:
                continue
            sport, dport, ulen = struct.unpack_from(">HHH", buf, u)
            if ulen < 8:
                continue
            yield src, dst, sport, dport, buf[u + 8:u + ulen]


def main():
    dtls = defaultdict(lambda: {"n": 0, "hs": set(), "ct": set(),
                                "app": 0, "first": None, "last": 0.0})
    stun = defaultdict(int)
    n = 0
    for src, dst, sp, dp, pl in read_pcap(PCAP):
        n += 1
        if is_dtls(pl):
            k = (src, sp, dst, dp)
            e = dtls[k]
            e["n"] += 1
            i = 0
            while i + 13 <= len(pl):
                ct, ln = pl[i], int.from_bytes(pl[i + 11:i + 13], "big")
                if ct not in CT or i + 13 + ln > len(pl):
                    break
                e["ct"].add(CT[ct])
                if ct == 22 and ln >= 4:
                    e["hs"].add(HS.get(pl[i + 13], "hs=%d" % pl[i + 13]))
                if ct == 23:
                    e["app"] += 1
                if e["first"] is None:
                    e["first"] = i == 0
                i += 13 + ln
        elif is_stun(pl):
            stun[(src, sp, dst, dp)] += 1

    print("pcap packets read: %d" % n)
    print("\n=== DTLS conversations (%d) ===" % len(dtls))
    for (s, sp, d, dp), e in sorted(dtls.items(), key=lambda x: -x[1]["n"]):
        print("  %s:%-6s -> %s:%-6s  pkts=%-5d appdata=%-5d ct={%s} hs={%s}"
              % (s, sp, d, dp, e["n"], e["app"],
                 ",".join(sorted(e["ct"])), ",".join(sorted(e["hs"]))))
    print("\n=== STUN conversations (%d) ===" % len(stun))
    for (s, sp, d, dp), c in sorted(stun.items(), key=lambda x: -x[1])[:20]:
        print("  %s:%-6s -> %s:%-6s  pkts=%d" % (s, sp, d, dp, c))


if __name__ == "__main__":
    main()
