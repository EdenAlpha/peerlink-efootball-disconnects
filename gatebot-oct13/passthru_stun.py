#!/usr/bin/env python3
"""passthru_stun.py -- decode STUN/TURN messages out of passthrough_capture.csv

Each CSV row's payload_hex is a complete IP packet. We parse IP/UDP and, when
the UDP payload looks like STUN (magic cookie 0x2112A442 at offset 4) or TURN
ChannelData, decode header + attributes with Konami's RP_ table.

  python passthru_stun.py <capture.csv> [sport|dport filter]
"""
import csv
import socket
import struct
import sys

ATTR = {
    0x0001: "MAPPED_ADDRESS", 0x0002: "RESPONSE_ADDRESS",
    0x0003: "CHANGE_ADDRESS", 0x0004: "SOURCE_ADDRESS",
    0x0005: "CHANGED_ADDRESS", 0x0006: "USERNAME", 0x0007: "PASSWORD",
    0x0008: "MESSAGE_INTEGRITY", 0x0009: "ERROR_CODE",
    0x000A: "UNKNOWN_ATTRIBUTES", 0x000B: "REFLECTED_FROM",
    0x000C: "CHANNEL_NUMBER", 0x000D: "LIFETIME", 0x0012: "XOR_PEER_ADDRESS",
    0x0013: "DATA", 0x0014: "REALM", 0x0015: "NONCE",
    0x0016: "XOR_RELAYED_ADDRESS", 0x0017: "REQUESTED_ADDRESS_FAMILY",
    0x0018: "EVEN_PORT", 0x0019: "REQUESTED_TRANSPORT",
    0x001A: "DONT_FRAGMENT", 0x0020: "XOR_MAPPED_ADDRESS",
    0x0022: "RESERVATION_TOKEN", 0x0026: "PADDING",
    0x0027: "RESPONSE_PORT", 0x002A: "CONNECTION_ID",
    0x8020: "XOR_MAPPED_ADDRESS_3489", 0x8022: "SOFTWARE",
    0x8023: "ALTERNATE_SERVER", 0x8028: "FINGERPRINT",
    0x802B: "RESPONSE_ORIGIN", 0x802C: "OTHER_ADDRESS",
    0x9090: "RP_P2P_HEADER", 0x9091: "RP_RELIABILITY",
    0x9092: "RP_AMF_DATA", 0x9093: "RP_JSON_DATA",
    0x9094: "RP_HOST_ADDRESS", 0x9095: "RP_REFLEXIVE_ADDRESS",
    0x9096: "RP_RELAYED_ADDRESS", 0x9097: "RP_NAT_TYPE",
    0x9098: "RP_SYNC_POINT", 0x9099: "RP_ENTRY_IDX",
    0x909A: "RP_PEER_STATUS", 0x909B: "RP_RAND_SEED",
    0x909C: "RP_RELIABILITY_ECHO", 0x909D: "UHP_FINALIZE_RET",
    0x9999: "TERM", 0xF000: "ATTR_EXTENSION",
}
MAGIC = b"\x21\x12\xa4\x42"


def msg_type_name(t):
    meth = (t & 0x000F) | ((t & 0x00E0) >> 1) | ((t & 0x3E00) >> 2)
    cls = (t & 0x0100) | (t & 0x0010)
    cn = {0x000: "REQ", 0x010: "IND", 0x100: "RES", 0x110: "ERR"}.get(
        cls, "C?%x" % cls)
    return "type=0x%04x(meth=0x%x,%s)" % (t, meth, cn)


def decode_addr(v, xor=False):
    if len(v) < 4:
        return v.hex()
    fam = v[1]
    port = struct.unpack(">H", v[2:4])[0]
    if xor:
        port ^= 0x2112
    if fam == 1 and len(v) >= 8:
        raw = v[4:8]
        if xor:
            raw = bytes(a ^ b for a, b in zip(raw, MAGIC))
        return "%s:%d" % (socket.inet_ntoa(raw), port)
    if fam == 2 and len(v) >= 20:
        return "[v6]:%d %s" % (port, v[4:20].hex())
    return "fam=%d %s" % (fam, v.hex())


def decode_attr(code, v):
    nm = ATTR.get(code, "?0x%04x" % code)
    if code in (0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x000B):
        return "%s=%s" % (nm, decode_addr(v))
    if code in (0x0020, 0x8020, 0x0012, 0x0016):
        return "%s=%s" % (nm, decode_addr(v, xor=True))
    if code in (0x9094, 0x9095, 0x9096) and len(v) >= 8:
        port = struct.unpack(">H", v[2:4])[0]
        if v[1] == 1 and len(v) >= 8:
            return "%s=v%d fam%d %s:%d  raw=%s" % (
                nm, v[0], v[1], socket.inet_ntoa(v[4:8]), port, v.hex())
        return "%s=v%d fam%d port%d %s" % (nm, v[0], v[1], port, v.hex())
    if code == 0x9097:
        return "%s=%s" % (nm, v.hex())
    if code in (0x0006, 0x0014, 0x0015, 0x8022):
        return "%s=%r" % (nm, v)
    return "%s len=%d %s" % (nm, len(v), v[:32].hex() +
                             ("..." if len(v) > 32 else ""))


def parse_udp_payload(p, meta):
    out = []
    if len(p) < 8:
        return out
    if (p[0] & 0xC0) == 0x40 and (p[2] == 0 or (p[2] & 0xC0) == 0x40):
        ch = struct.unpack(">H", p[:2])[0]
        out.append("CHDATA %s ch=0x%04x len=%d %s" %
                   (meta, ch, struct.unpack(">H", p[2:4])[0],
                    p[4:24].hex()))
        return out
    if p[4:8] != MAGIC or (p[0] & 0xC0):
        return out
    t, ln = struct.unpack(">HH", p[:4])
    out.append("STUN %s %s msglen=%d tid=%s" %
               (meta, msg_type_name(t), ln, p[8:20].hex()))
    off = 20
    end = min(len(p), 20 + ln)
    while off + 4 <= end:
        code, alen = struct.unpack(">HH", p[off:off + 4])
        val = p[off + 4:off + 4 + alen]
        out.append("      %s" % decode_attr(code, val))
        off += 4 + ((alen + 3) & ~3)
    if off < end:
        out.append("      trailing=%s" % p[off:end].hex())
    return out


def main():
    path = sys.argv[1]
    portf = sys.argv[2] if len(sys.argv) > 2 else None
    n = stun = other = 0
    with open(path, newline="") as fh:
        rdr = csv.DictReader(l for l in fh if not l.startswith("#"))
        for row in rdr:
            n += 1
            hx = row.get("payload_hex") or ""
            if len(hx) < 40:
                continue
            pkt = bytes.fromhex(hx)
            if (pkt[0] >> 4) != 4:
                continue
            ihl = (pkt[0] & 0xF) * 4
            if pkt[9] != 17:
                continue
            udp = pkt[ihl:]
            if len(udp) < 8:
                continue
            sport, dport = struct.unpack(">HH", udp[:4])
            if portf and str(sport) != portf and str(dport) != portf:
                continue
            meta = "%s %s:%d->%s:%d" % (row["dir"], row["src"], sport,
                                        row["dst"], dport)
            lines = parse_udp_payload(udp[8:], meta)
            if lines:
                stun += 1
                print("\n".join(lines))
            else:
                other += 1
                if other <= 6 and udp[8:]:
                    print("OTHER %s first8=%s" % (meta, udp[8:16].hex()))
    print("-- rows=%d stun=%d other-udp=%d" % (n, stun, other))


if __name__ == "__main__":
    main()
