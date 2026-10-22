#!/usr/bin/env python3
"""Host-side Konami STUN fabricator - 1:1 port of PeerLink StunFabricator.kt.

Faithful to what the app runs in the phone: same clusters, same request
classification (T1..T7), same RFC 5780 partner rules, same attribute order,
same checksums. The parity test (test_fabricator_parity.py) asserts every
behaviour against the app's own regression matrix (StunFabricatorChecks.kt).

Differences vs the app are transport only: this runs on the container host
(TPROXY receive + raw datagram send) and can optionally answer STUN sent to
addresses outside the four verified clusters with a generic single-server
profile (that path is off in strict mode, which is what the parity test
exercises).

Key rule kept identical to NativePeerLinkBackend.kt:245:
    reported mapped address = (fabricated IP, the game's own source port).
"""

import struct
import zlib

MAGIC_COOKIE = b"\x21\x12\xa4\x42"
MAGIC_PORT_XOR = 0x2112
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101

ATTR_MAPPED = 0x0001
ATTR_CHANGE_REQ = 0x0003
ATTR_XOR_MAPPED = 0x0020
ATTR_RESPONSE_PORT = 0x0027
ATTR_SOFTWARE = 0x8022
ATTR_FINGERPRINT = 0x8028
ATTR_RESPONSE_ORIGIN = 0x802B
ATTR_OTHER_ADDRESS = 0x802C
ATTR_KONAMI_EXT = 0xF000

T_KONAMI, T_RESP_PORT, T_BARE, T_CHG_BOTH, T_CHG_IP, T_CHG_PORT, T_SIGNALING = range(1, 8)
TYPE_NAMES = {T_KONAMI: "Konami", T_RESP_PORT: "RespPort", T_BARE: "Bare",
              T_CHG_BOTH: "ChgBoth", T_CHG_IP: "ChgIP", T_CHG_PORT: "ChgPort",
              T_SIGNALING: "Signaling"}

SOFTWARE = bytes([
    0x54, 0x75, 0x72, 0x6E, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
    0x20, 0x30, 0x2E, 0x37, 0x2E, 0x32, 0x2B, 0x30, 0x33,
])

CLUSTERS = [
    ("54.248.105.235", "54.150.255.185", "52.198.221.89"),
    ("18.176.255.15", "54.199.110.22", "3.113.89.160"),
    ("35.76.243.83", "54.150.169.24", "54.65.202.22"),
    ("54.64.79.140", "13.230.144.13", "176.34.63.31"),
]
SERVER_PORTS = (3478, 3479)

CLASS_UNKNOWN_DONT_FABRICATE = object()


# ---------------------------------------------------------------- byte utils

def u16(b, o):
    return (b[o] << 8) | b[o + 1]


def u32(b, o):
    return (u16(b, o) << 16) | u16(b, o + 2)


def ip_bytes(ip):
    return bytes(int(x) & 0xFF for x in ip.split("."))


def inet_checksum(data):
    total = 0
    for i in range(0, len(data) - 1, 2):
        total += (data[i] << 8) | data[i + 1]
    if len(data) & 1:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


# ------------------------------------------------------------------- parsing

class Parsed:
    __slots__ = ("txn", "msg_len", "attrs", "konami_ext",
                 "response_port", "change_flags")


def parse_stun_request(data, offset=0, length=None):
    """Kotlin parseStunRequest, line for line. Returns Parsed or None."""
    if length is None:
        length = len(data) - offset
    if offset < 0 or length < 20 or offset > len(data) - length:
        return None
    if u32(data, offset + 4) != 0x2112A442:
        return None
    if u16(data, offset) != BINDING_REQUEST:
        return None
    msg_len = u16(data, offset + 2)
    if (msg_len & 3) != 0 or msg_len != length - 20:
        return None

    p = Parsed()
    p.txn = bytes(data[offset + 8:offset + 20])
    p.msg_len = msg_len
    p.attrs = {}
    p.konami_ext = False
    p.response_port = 0
    p.change_flags = 0

    pos = offset + 20
    end = offset + 20 + msg_len
    while pos < end:
        if end - pos < 4:
            return None
        attr_type = u16(data, pos)
        attr_len = u16(data, pos + 2)
        padded = (attr_len + 3) & 0x7FFFFFFC
        if padded > end - pos - 4:
            return None
        # No credentials or padding policy are implemented here. Preserve
        # the real server path for unsupported comprehension-required attrs.
        if attr_type < 0x8000 and attr_type not in (ATTR_CHANGE_REQ,
                                                    ATTR_RESPONSE_PORT):
            return None
        if attr_type == ATTR_CHANGE_REQ and attr_len != 4:
            return None
        if attr_type == ATTR_RESPONSE_PORT:
            if attr_len != 4:
                return None
            if u16(data, pos + 4) == 0:
                return None
        if attr_type == ATTR_FINGERPRINT:
            if attr_len != 4 or pos + 8 != end:
                return None
            if u32(data, pos + 4) != (crc32(bytes(data[offset:pos]))
                                      ^ 0x5354554E):
                return None
        value = bytes(data[pos + 4:pos + 4 + attr_len])
        # STUN uses the first occurrence of an attribute, not the last.
        if attr_type not in p.attrs:
            p.attrs[attr_type] = value
            if attr_type == ATTR_KONAMI_EXT:
                p.konami_ext = True
            elif attr_type == ATTR_RESPONSE_PORT:
                p.response_port = u16(data, pos + 4)
            elif attr_type == ATTR_CHANGE_REQ:
                p.change_flags = u32(data, pos + 4)
        pos += 4 + padded
    return p


def classify_request(p):
    if ATTR_CHANGE_REQ in p.attrs:
        flags = p.change_flags & 0x06
        if flags == 0x06:
            return T_CHG_BOTH
        if flags == 0x04:
            return T_CHG_IP
        if flags == 0x02:
            return T_CHG_PORT
        return T_BARE
    if ATTR_RESPONSE_PORT in p.attrs:
        return T_RESP_PORT
    if 0x9090 in p.attrs or 0x9091 in p.attrs:
        return T_SIGNALING
    if p.konami_ext:
        return T_KONAMI
    if p.msg_len == 0:
        return T_BARE
    return T_KONAMI


# ------------------------------------------- cluster / reply-source decision

def cluster_for(dest_ip):
    for c in CLUSTERS:
        if dest_ip in c:
            return c
    return None


def partner_ip(dest_ip, cluster):
    if dest_ip == cluster[0]:
        return cluster[1]
    if dest_ip == cluster[1]:
        return cluster[0]
    return cluster[1]


def partner_port(dest_port, cluster=SERVER_PORTS):
    return SERVER_PORTS[1] if dest_port == SERVER_PORTS[0] else SERVER_PORTS[0]


def response_destination_port(p, request_source_port):
    if ATTR_RESPONSE_PORT in p.attrs:
        return p.response_port
    return request_source_port


def response_source(dest_ip, dest_port, p, cluster):
    other_ip = partner_ip(dest_ip, cluster)
    other_port = partner_port(dest_port)
    src_ip = other_ip if (p.change_flags & 0x04) else dest_ip
    src_port = other_port if (p.change_flags & 0x02) else dest_port
    # RFC 5780 table 1: OTHER-ADDRESS always refers to the alternative
    # of the REQUEST destination, regardless of the selected reply source.
    # RESPONSE-PORT is independent and changes only the reply destination.
    return (src_ip, src_port, src_ip, src_port, other_ip, other_port)


# ------------------------------------------------------------- attr builders

def _attr(type_id, value, pad_to=None):
    total = pad_to if pad_to else ((len(value) + 3) // 4) * 4
    out = bytearray(4 + total)
    out[0:2] = struct.pack(">H", type_id)
    out[2:4] = struct.pack(">H", len(value))
    out[4:4 + len(value)] = value
    return bytes(out)


def _v4_mapped(ip4):
    return b"\x00" * 10 + b"\xff\xff" + ip4


def build_xor_mapped(ip, port):
    ipb = ip_bytes(ip)
    val = struct.pack(">HH", 0x0001, port ^ MAGIC_PORT_XOR)
    val += bytes((ipb[i] ^ MAGIC_COOKIE[i]) for i in range(4))
    return _attr(ATTR_XOR_MAPPED, val)


def build_mapped(ip, port):
    return _attr(ATTR_MAPPED, struct.pack(">HH", 0x0001, port) + ip_bytes(ip))


def build_address(type_id, addr, port, ipv6=False):
    if ipv6:
        value = struct.pack(">HH", 0x0002, port) + addr
    else:
        value = struct.pack(">HH", 0x0001, port) + addr
    return _attr(type_id, value)


def build_fingerprint(message):
    fp = crc32(message) ^ 0x5354554E
    return _attr(ATTR_FINGERPRINT, struct.pack(">I", fp))


def build_stun_response(txn, fab_ip, fab_port, rsource, cluster,
                        include_konami_ext, ipv6_transport=False):
    attrs = [
        build_xor_mapped(fab_ip, fab_port),
        _attr(ATTR_SOFTWARE, SOFTWARE),
        build_mapped(fab_ip, fab_port),
    ]
    if ipv6_transport:
        origin = _v4_mapped(ip_bytes(rsource[2]))
        other = _v4_mapped(ip_bytes(rsource[4]))
    else:
        origin = ip_bytes(rsource[2])
        other = ip_bytes(rsource[4])
    attrs.append(build_address(ATTR_RESPONSE_ORIGIN, origin, rsource[3],
                               ipv6=ipv6_transport))
    attrs.append(build_address(ATTR_OTHER_ADDRESS, other, rsource[5],
                               ipv6=ipv6_transport))
    if include_konami_ext:
        value = bytes([0x05, 0x73, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03,
                       0x00, 0x01, 0x0D, 0x97]) + ip_bytes(cluster[2])
        attrs.append(_attr(ATTR_KONAMI_EXT, value))

    body = b"".join(attrs)
    head = struct.pack(">BBH", 0x01, 0x01, len(body) + 8) \
        + MAGIC_COOKIE + txn
    return head + body + build_fingerprint(head + body)


# ----------------------------------------------------------- packet builders

def ipv4_udp_checksum(src_ip, dst_ip, pkt, udp_off, udp_len):
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack(">BBH", 0, 17,
                                                               udp_len)
    body = bytearray(pkt[udp_off:udp_off + udp_len])
    body[6:8] = b"\x00\x00"
    return inet_checksum(pseudo + bytes(body))


def build_ipv4_udp(src_ip, dst_ip, src_port, dst_port, payload,
                   check_udp=True):
    udp_len = 8 + len(payload)
    pkt = bytearray(20 + udp_len)
    pkt[0] = 0x45
    pkt[1] = 0x00
    pkt[2:4] = struct.pack(">H", 20 + udp_len)
    pkt[6] = 0x40                      # Dont Fragment, like the app
    pkt[8] = 0x40                      # TTL 64
    pkt[9] = 17                        # UDP
    pkt[12:16] = ip_bytes(src_ip)
    pkt[16:20] = ip_bytes(dst_ip)
    pkt[20:22] = struct.pack(">H", src_port)
    pkt[22:24] = struct.pack(">H", dst_port)
    pkt[24:26] = struct.pack(">H", udp_len)
    pkt[28:] = payload
    pkt[10:12] = struct.pack(">H", inet_checksum(bytes(pkt[0:20])))
    if check_udp:
        pkt[26:28] = struct.pack(
            ">H", ipv4_udp_checksum(src_ip, dst_ip, pkt, 20, udp_len))
    return bytes(pkt)


def ipv6_udp_checksum(src_addr, dst_addr, pkt, udp_off, udp_len):
    pseudo = src_addr + dst_addr
    pseudo += len(pkt[udp_off:]).to_bytes(4, "big")
    pseudo = pseudo[:8] + b"\x00\x00\x00" + b"\x11"
    body = bytearray(pkt[udp_off:udp_off + udp_len])
    body[6:8] = b"\x00\x00"
    return inet_checksum(pseudo + bytes(body))


def build_ipv6_udp(src_addr, dst_addr, src_port, dst_port, payload):
    udp_len = 8 + len(payload)
    pkt = bytearray(40 + udp_len)
    pkt[0] = 0x60
    pkt[6] = 17
    pkt[7] = 64
    pkt[4:6] = struct.pack(">H", udp_len)
    pkt[8:24] = src_addr
    pkt[24:40] = dst_addr
    pkt[40:42] = struct.pack(">H", src_port)
    pkt[42:44] = struct.pack(">H", dst_port)
    pkt[44:46] = struct.pack(">H", udp_len)
    pkt[48:] = payload
    pkt[46:48] = struct.pack(
        ">H", ipv6_udp_checksum(src_addr, dst_addr, pkt, 40, udp_len))
    return bytes(pkt)


# --------------------------------------------------------------- wrappers

def parse_lan_ipv4_udp(raw, length=None):
    """Conservative(PacketParser-like) IPv4/UDP check for the parity tests."""
    if length is None:
        length = len(raw)
    if length < 0 or length > len(raw):
        return None
    if length < 28:
        return None
    if (raw[0] >> 4) != 4 or (raw[0] & 0x0F) != 5:
        return None
    total = u16(raw, 2)
    if total > length:
        return None
    if u16(raw, 6) & 0x3FFF:            # MF flag / fragment offset
        return None
    if raw[9] != 17:
        return None
    udp_len = u16(raw, 24)
    if udp_len < 8 or 20 + udp_len > total:
        return None
    return {
        "src": ".".join(str(raw[12 + i]) for i in range(4)),
        "dst": ".".join(str(raw[16 + i]) for i in range(4)),
        "sport": u16(raw, 20),
        "dport": u16(raw, 22),
        "offset": 28,
        "length": udp_len,              # full UDP length, header included
    }


def fabricate_ipv4_udp(raw_wrapper, fab_ip, fab_port=None):
    """Port of the app path: parse the wrapped request, answer one packet."""
    parsed = parse_lan_ipv4_udp(raw_wrapper)
    if parsed is None:
        return None
    body = bytes(raw_wrapper[parsed["offset"]:parsed["offset"]
                             + parsed["length"] - 8])
    if not body:
        return None
    p = parse_stun_request(body)
    if p is None:
        return None
    cluster = cluster_for(parsed["dst"])
    if cluster is None:
        return None
    if parsed["dport"] not in SERVER_PORTS:
        return None
    if fab_port is None:
        fab_port = parsed["sport"]
    if not 1 <= fab_port <= 65535:
        return None
    rsource = response_source(parsed["dst"], parsed["dport"], p, cluster)
    response = build_stun_response(p.txn, fab_ip, fab_port, rsource, cluster,
                                   p.konami_ext)
    reply_port = response_destination_port(p, parsed["sport"])
    return build_ipv4_udp(rsource[0], parsed["src"], rsource[1], reply_port,
                          response)


def generic_answer(body, dst_ip, dst_port, fab_ip):
    """For STUN aimed outside the four clusters (used only after
    enumeration shows the game really sends it). Same shape as the proven
    profile, but every server field mirrors the actual destination."""
    p = parse_stun_request(body)
    if p is None:
        return None
    if dst_port not in SERVER_PORTS:
        return None
    alt = SERVER_PORTS[1] if dst_port == SERVER_PORTS[0] else SERVER_PORTS[0]
    rsource = (dst_ip, dst_port, dst_ip, dst_port, dst_ip, alt)
    return build_stun_response(p.txn, fab_ip, None, rsource,
                               (dst_ip, dst_ip, dst_ip), p.konami_ext)


def fabricate_ipv6(v6_packet, fab_ip, fab_port):
    """Port of fabricateIpv6StunResponse - returns full IPv6 packet or None."""
    if len(v6_packet) < 68 or (v6_packet[0] >> 4) != 6:
        return None
    if v6_packet[6] != 17:
        return None
    dst_port = u16(v6_packet, 42)
    if dst_port not in (3478, 3479, 3480, 3481):
        port_ok = dst_port in range(19302, 19310)
        if not port_ok:
            return None
    ip_len = u16(v6_packet, 4)
    if ip_len < 28 or ip_len > len(v6_packet) - 40:
        return None
    udp_len = u16(v6_packet, 44)
    if udp_len < 28 or udp_len > ip_len:
        return None
    client = bytes(v6_packet[8:24])
    server = bytes(v6_packet[24:40])
    if not (all(b == 0 for b in server[0:10]) and server[10] == 0xFF
            and server[11] == 0xFF):
        return None
    server_ipv4 = ".".join(str(server[12 + i]) for i in range(4))
    cluster = cluster_for(server_ipv4)
    if cluster is None:
        return None
    src_port = u16(v6_packet, 40)
    if dst_port not in SERVER_PORTS:
        return None
    p = parse_stun_request(v6_packet[48:48 + udp_len - 8], 0, udp_len - 8)
    if p is None:
        return None
    rsource = response_source(server_ipv4, dst_port, p, cluster)
    response = build_stun_response(p.txn, fab_ip, fab_port, rsource, cluster,
                                   p.konami_ext, ipv6_transport=True)
    return build_ipv6_udp(_v4_mapped(ip_bytes(rsource[0])), client,
                          rsource[1], response_destination_port(p, src_port),
                          response)
