#!/usr/bin/env python3
"""pcapng_read.py -- read the tunnel underlay wire (m4/m5 tunnel_capture.pcapng).

No tshark on this box necessarily; parse pcapng by hand (SHB/IDB/EPB/SPB),
then fingerprint every UDP payload: PeerLink underlay header? inner game
bytes (STUN magic / DTLS / punch 0x080b)?

  python pcapng_read.py [m4|m5|both]
"""
import struct
import sys
from collections import Counter

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"


def read_pcapng(path):
    data = open(path, "rb").read()
    pkts = []
    off = 0
    endian = "<"
    while off + 12 <= len(data):
        blk, blen = struct.unpack(endian + "II", data[off:off + 8])
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if blk == 0x0A0D4A0D:                      # SHB
            if len(body) >= 4 and body[:4] == b"\x1a\x2b\x3c\x4d":
                endian = ">"
        elif blk in (0x00000006, 0x00000003):      # EPB / SPB
            if blk == 0x00000006:
                _if, _ts1, _ts2, caplen, _len = struct.unpack(
                    endian + "IIIII", body[:20])
                pkt = body[20:20 + caplen]
            else:
                _len, _ = struct.unpack(endian + "II", body[:8])
                pkt = body[8:8 + _len]
            pkts.append(pkt)
        off += blen
    return pkts


def fp(payload):
    if len(payload) < 4:
        return "tiny<%d>" % len(payload)
    if payload[:2] == b"\x16\x03":
        return "TLS-hs?"
    if len(payload) >= 13 and payload[0] in (20, 21, 22, 23) and \
            payload[1:3] in (b"\xfe\xff", b"\xfe\xfd"):
        return "DTLS-" + {22: "hs", 23: "app", 21: "alrt"}.get(
            payload[0], "?")
    if len(payload) >= 20 and payload[4:8] == b"\x21\x12\xa4\x42":
        return "STUN/0x%04x" % struct.unpack("!H", payload[:2])[0]
    return "opaque 0x%02x" % payload[0]


def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    ms = ("m4", "m5") if which == "both" else (which,)
    for m in ms:
        pkts = read_pcapng(D + "\\%s\\tunnel_capture.pcapng" % m)
        print("=== %s: %d packets ===" % (m, len(pkts)))
        flows = Counter()
        fps = Counter()
        first = {}
        for pkt in pkts:
            if len(pkt) < 42:
                continue
            # assume Ethernet(14) + IPv4; fall back to raw IP
            if pkt[12:14] == b"\x08\x00":
                ip = pkt[14:]
            elif (pkt[0] >> 4) == 4:
                ip = pkt
            else:
                continue
            ihl = (ip[0] & 0xF) * 4
            proto = ip[9]
            if proto != 17 or len(ip) < ihl + 8:
                continue
            sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])
            body = ip[ihl + 8:]
            flows[(src, sport, dst, dport)] += 1
            f = fp(body)
            fps[f] += 1
            if (src, dport) not in first and len(body) >= 20:
                first[(src, dport)] = body[:64].hex()
        print("  flows:")
        for k, c in flows.most_common(12):
            print("    %6d  %s:%s -> %s:%s" % (c, k[0], k[1], k[2], k[3]))
        print("  fingerprints:", dict(fps.most_common(12)))
        for k, h in list(first.items())[:8]:
            print("  first %s:%s: %s" % (k[0], k[1], h[:96]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
