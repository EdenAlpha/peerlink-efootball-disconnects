#!/usr/bin/env python3
"""stun_extract.py -- pull every STUN/TURN-shaped UDP payload out of a pcap
and decode headers + attributes with Konami's RP_ code table.

  python stun_extract.py <file.pcap[.gz]>
"""
import gzip
import socket
import struct
import sys

import dpkt

ATTR = {
    0x0001: "MAPPED_ADDRESS", 0x0002: "RESPONSE_ADDRESS",
    0x0003: "CHANGE_ADDRESS", 0x0004: "SOURCE_ADDRESS",
    0x0005: "CHANGED_ADDRESS", 0x0006: "USERNAME", 0x0007: "PASSWORD",
    0x0008: "MESSAGE_INTEGRITY", 0x0009: "ERROR_CODE",
    0x000A: "UNKNOWN_ATTRIBUTES", 0x000B: "REFLECTED_FROM",
    0x000C: "CHANNEL_NUMBER", 0x000D: "LIFETIME",
    0x0012: "XOR_PEER_ADDRESS", 0x0013: "DATA", 0x0014: "REALM",
    0x0015: "NONCE", 0x0016: "XOR_RELAYED_ADDRESS",
    0x0017: "REQUESTED_ADDRESS_FAMILY", 0x0018: "EVEN_PORT",
    0x0019: "REQUESTED_TRANSPORT", 0x001A: "DONT_FRAGMENT",
    0x0020: "XOR_MAPPED_ADDRESS", 0x0022: "RESERVATION_TOKEN",
    0x0026: "PADDING", 0x0027: "RESPONSE_PORT", 0x002A: "CONNECTION_ID",
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
    return "0x%04x(meth=0x%x,%s)" % (t, meth, cn)


def decode_addr(v, xor=False, magic=MAGIC):
    if len(v) < 4:
        return v.hex()
    fam = v[1]
    port = struct.unpack(">H", v[2:4])[0]
    if xor:
        port ^= struct.unpack(">H", magic[:2])[0]
    if fam == 1 and len(v) >= 8:
        ip = socket.inet_ntoa(bytes(a ^ b for a, b in
                                    zip(v[4:8], magic)))
        return "%s:%d" % (ip, port)
    if fam == 2 and len(v) >= 20:
        return "[%s]:%d" % (":".join("%x" % struct.unpack(
            ">H", bytes(a ^ b for a, b in zip(v[4 + i:6 + i],
                                              magic[i:i + 2])))[0]
            for i in range(0, 16, 2)), port)
    return "fam=%d %s" % (fam, v.hex())


def decode_attr(code, v):
    nm = ATTR.get(code, "?0x%04x" % code)
    if code in (0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x000B):
        return "%s=%s" % (nm, decode_addr(v))
    if code in (0x0020, 0x8020, 0x0012, 0x0016):
        return "%s=%s" % (nm, decode_addr(v, xor=True))
    if code in (0x9094, 0x9095, 0x9096) and len(v) >= 8:
        # [type u8][family u8][port u16][addr...]
        port = struct.unpack(">H", v[2:4])[0]
        if v[1] == 1 and len(v) >= 8:
            ip = socket.inet_ntoa(v[4:8])
            return "%s=v%d fam%d %s:%d" % (nm, v[0], v[1], ip, port)
        return "%s=v%d fam%d port%d %s" % (nm, v[0], v[1], port, v[4:].hex())
    if code == 0x9097 and len(v) <= 8:
        return "%s=%s" % (nm, v.hex())
    return "%s[%d]=%s" % (nm, len(v), v[:24].hex() +
                          ("..." if len(v) > 24 else ""))


def walk(buf):
    ip = None
    try:
        if isinstance(buf, bytes) and len(buf) > 0 and (buf[0] >> 4) == 4:
            ip = dpkt.ip.IP(buf)
        else:
            return None
    except Exception:
        return None
    if not isinstance(ip.data, dpkt.udp.UDP):
        return None
    udp = ip.data
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    p = bytes(udp.data)
    if len(p) < 8:
        return None
    # TURN ChannelData: top 2 bits 01, len at [2:4]
    if (p[0] & 0xC0) == 0x40 and (p[2] == 0 or p[2] == 0x40):
        return ("CHDATA %s:%d -> %s:%d ch=0x%04x payload=%d %s"
                % (src, udp.sport, dst, udp.dport,
                   struct.unpack(">H", p[:2])[0],
                   struct.unpack(">H", p[2:4])[0], p[4:20].hex()))
    if p[4:8] != MAGIC or (p[0] & 0xC0):
        return None
    t, ln = struct.unpack(">HH", p[:4])
    tid = p[8:20].hex()
    attrs = []
    off = 20
    while off + 4 <= min(len(p), 20 + ln):
        code, alen = struct.unpack(">HH", p[off:off + 4])
        val = p[off + 4:off + 4 + alen]
        attrs.append(decode_attr(code, val))
        off += 4 + ((alen + 3) & ~3)
    lines = ["STUN %s:%d -> %s:%d %s len=%d tid=%s"
             % (src, udp.sport, dst, udp.dport, msg_type_name(t), ln,
                tid[:24])]
    lines += ["      %s" % a for a in attrs]
    return "\n".join(lines)


path = sys.argv[1]
op = gzip.open if path.endswith(".gz") else open
with op(path, "rb") as f:
    pcap = dpkt.pcap.Reader(f)
    n = stun = 0
    for ts, buf in pcap:
        n += 1
        out = walk(buf)
        if out:
            stun += 1
            sys.stdout.write(out + "\n")
    print("-- packets=%d stun-ish=%d" % (n, stun))
