#!/usr/bin/env python3
"""Parity test: the same matrix the app runs in StunFabricatorChecks.kt,
assertion for assertion, against this host-side port. Run: python3 test.
Exit 0 == the port is byte-compatible with the proven Kotlin fabricator."""

import struct
import sys
import zlib

import fabricator as F

ASSERTIONS = 0


def expect(ok, message):
    global ASSERTIONS
    ASSERTIONS += 1
    if not ok:
        print("FAIL:", message)
        raise SystemExit(1)


def u16(b, o):
    return (b[o] << 8) | b[o + 1]


def u32(b, o):
    return (u16(b, o) << 16) | u16(b, o + 2)


def w16(b, o, v):
    b[o] = (v >> 8) & 0xFF
    b[o + 1] = v & 0xFF


def w32(b, o, v):
    w16(b, o, (v >> 16) & 0xFFFF)
    w16(b, o + 2, v & 0xFFFF)


def ip(s):
    return bytes(int(x) for x in s.split("."))


def mapped(s):
    out = bytearray(16)
    out[10] = 0xFF
    out[11] = 0xFF
    out[12:16] = ip(s)
    return bytes(out)


def attr(type_id, value):
    pad = ((len(value) + 3) // 4) * 4
    out = bytearray(4 + pad)
    w16(out, 0, type_id)
    w16(out, 2, len(value))
    out[4:4 + len(value)] = value
    return bytes(out)


def int_attr(type_id, v):
    return attr(type_id, struct.pack(">I", v))


def port_attr(v):
    return attr(0x0027, struct.pack(">I", v << 16))


def request(*attrs):
    body = b"".join(attrs)
    out = bytearray(20 + len(body))
    w16(out, 0, 1)
    w16(out, 2, len(body))
    w32(out, 4, 0x2112A442)
    for i in range(8, 20):
        out[i] = i
    out[20:] = body
    return bytes(out)


def packet(payload, server="18.176.255.15", server_port=3478,
           local_port=56008):
    out = bytearray(28 + len(payload))
    out[0] = 0x45
    out[8] = 64
    out[9] = 17
    w16(out, 2, len(out))
    out[12:16] = ip("10.0.0.2")
    out[16:20] = ip(server)
    w16(out, 20, local_port)
    w16(out, 22, server_port)
    w16(out, 24, 8 + len(payload))
    out[28:] = payload
    return bytes(out)


def reply(raw):
    parsed = F.parse_lan_ipv4_udp(raw, len(raw))
    if parsed is None:
        return None
    body = raw[parsed["offset"]:parsed["offset"] + parsed["length"] - 8]
    src_port = parsed["sport"]
    fab_port = src_port                       # NativePeerLinkBackend.kt:245
    cluster = F.cluster_for(parsed["dst"])
    if cluster is None or parsed["dport"] not in F.SERVER_PORTS:
        return None
    p = F.parse_stun_request(body)
    if p is None:
        return None
    rsource = F.response_source(parsed["dst"], parsed["dport"], p, cluster)
    response = F.build_stun_response(p.txn, "203.0.113.1", fab_port, rsource,
                                     cluster, p.konami_ext)
    reply_port = F.response_destination_port(p, src_port)
    return F.build_ipv4_udp(rsource[0], parsed["src"], rsource[1], reply_port,
                            response)


def attributes(raw, start):
    end = start + 20 + u16(raw, start + 2)
    expect(end == len(raw), "response STUN length must match UDP body")
    found = {}
    pos = start + 20
    while pos < end:
        type_id = u16(raw, pos)
        length = u16(raw, pos + 2)
        expect(pos + 4 + length <= end, "response attribute bounds")
        found[type_id] = raw[pos + 4:pos + 4 + length]
        pos += 4 + ((length + 3) // 4) * 4
    expect(pos == end, "response attribute alignment")
    expect(list(found.keys())[-1] == 0x8028, "fingerprint must be last")
    crc = zlib.crc32(raw[start:end - 8]) ^ 0x5354554E
    expect(u32(raw, end - 4) == crc, "independent CRC32 fingerprint")
    return found


def checksum16(data, start=0, length=None):
    if length is None:
        length = len(data) - start
    total = 0
    i = start
    while i + 1 < start + length:
        total += u16(data, i)
        i += 2
    if i < start + length:
        total += data[i] << 8
    while (total >> 16) != 0:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def address(value, expected_ip, port, family=1):
    expect(len(value) == 4 + len(expected_ip) and value[1] == family,
           "address family/size")
    expect(u16(value, 2) == port, "address attribute port")
    expect(value[4:] == expected_ip, "address attribute IP")


def verify_all():
    profiles = [
        ("54.248.105.235", "54.150.255.185", "52.198.221.89"),
        ("18.176.255.15", "54.199.110.22", "3.113.89.160"),
        ("35.76.243.83", "54.150.169.24", "54.65.202.22"),
        ("54.64.79.140", "13.230.144.13", "176.34.63.31"),
    ]
    for profile in profiles:
        for reverse in (False, True):
            server = profile[1] if reverse else profile[0]
            partner = profile[0] if reverse else profile[1]
            for server_port in (3478, 3479):
                for flags in (0, 2, 4, 6):
                    for target_port in (56008, 61000):
                        change = int_attr(3, flags)
                        req = (request(change) if target_port == 56008
                               else request(change, port_attr(target_port)))
                        response = reply(packet(req, server, server_port))
                        expect(response is not None,
                               f"missing response {server}:{server_port} "
                               f"flags={flags}")
                        expected_source = partner if flags in (4, 6) else server
                        other_port = 3479 if server_port == 3478 else 3478
                        expected_source_port = (
                            other_port if flags in (2, 6) else server_port)
                        expect(response[12:16] == ip(expected_source),
                               "CHANGE_REQUEST source IP")
                        expect(response[16:20] == ip("10.0.0.2"),
                               "reply to original local address")
                        expect(u16(response, 20) == expected_source_port,
                               "CHANGE_REQUEST source port")
                        expect(u16(response, 22) == target_port,
                               "RESPONSE_PORT changes destination only")
                        expect(u16(response, 28) == 0x0101,
                               "Binding success message type")
                        expect(response[36:48] == req[8:20],
                               "transaction ID preserved")
                        expect(checksum16(response, 0, 20) == 0xFFFF,
                               "IPv4 header checksum")
                        pseudo = (response[12:20] + bytes([0, 17])
                                  + response[24:26])
                        expect(checksum16(pseudo + response[20:])
                               == 0xFFFF, "UDP checksum")
                        attrs = attributes(response, 28)
                        address(attrs[0x802B], ip(expected_source),
                                expected_source_port)
                        address(attrs[0x802C], ip(partner), other_port)
                        address(attrs[0x0001], ip("203.0.113.1"), 56008)
                        xor = attrs[0x0020]
                        expect((u16(xor, 2) ^ 0x2112) == 56008,
                               "mapped port is request source, "
                               "not RESPONSE_PORT")
                        cookie = bytes([0x21, 0x12, 0xA4, 0x42])
                        decoded = bytes(xor[4 + i] ^ cookie[i]
                                        for i in range(4))
                        expect(decoded == ip("203.0.113.1"), "XOR-MAPPED addr")

            ext = reply(packet(request(attr(0xF000, bytes(16))), server))
            expect(ext is not None, "F000 response missing")
            got = attributes(ext, 28)[0xF000][12:16]
            expect(got == ip(profile[2]),
                   "capture-backed third-server address")

    plain = packet(request())
    first = reply(plain)
    for _ in range(100):
        expect(reply(plain) == first,
               "immediate retry must reproduce response")
    expect(u16(reply(packet(request(), local_port=56009)), 22) == 56009,
           "same TxID on different socket is not suppressed")
    r = reply(packet(request(port_attr(61000))))
    expect(u16(r, 20) == 3478 and u16(r, 22) == 61000,
           "RESPONSE_PORT without CHANGE_REQUEST")
    expect(u16(reply(packet(request(int_attr(3, 2), int_attr(3, 4)))), 20)
           == 3479, "first duplicate attribute wins")
    expect(reply(packet(request(), "192.0.2.123")) is None,
           "unknown server cannot inherit an unrelated cluster")
    expect(reply(packet(request(), server_port=3481)) is None,
           "unknown server-port pairing is passed through")
    expect(reply(packet(request(port_attr(0)))) is None,
           "zero response port must not silently select another port")
    expect(reply(packet(request(attr(0x0011, b"")))) is None,
           "unknown required attribute is not fabricated")
    expect(reply(packet(request(attr(0x0008, bytes(20))))) is None,
           "authenticated request goes to real server")
    expect(reply(packet(request(int_attr(0x0026, 0), port_attr(61000)))) is None,
           "padding with response port is not fabricated")
    short = bytearray(request())
    w16(short, 2, 4)
    expect(reply(packet(bytes(short))) is None,
           "declared message outside UDP bounds")
    malformed = bytearray(request(int_attr(3, 2)))
    w16(malformed, 22, 0xFFFF)
    expect(reply(packet(bytes(malformed))) is None,
           "attribute exceeds declared message")
    expect(reply(packet(request() + bytes([1, 2, 3, 4]))) is None,
           "trailing bytes cannot extend declared message")
    fpd = bytearray(request(attr(0x8028, bytes(4))))
    crc = zlib.crc32(bytes(fpd[:len(fpd) - 8])) ^ 0x5354554E
    w32(fpd, len(fpd) - 4, crc)
    expect(reply(packet(bytes(fpd))) is not None,
           "valid request fingerprint accepted")
    fpd[-1] ^= 1
    expect(reply(packet(bytes(fpd))) is None,
           "invalid request fingerprint rejected")

    p = packet(request())
    expect(F.parse_lan_ipv4_udp(p, len(p) + 1) is None,
           "raw packet length larger than array rejected")
    expect(F.parse_lan_ipv4_udp(p, -1) is None,
           "negative packet length rejected")
    bad_ip = bytearray(p)
    w16(bad_ip, 2, 60000)
    expect(F.parse_lan_ipv4_udp(bytes(bad_ip), len(bad_ip)) is None,
           "truncated IP rejected")
    fragment = bytearray(p)
    w16(fragment, 6, 1)
    expect(F.parse_lan_ipv4_udp(bytes(fragment), len(fragment)) is None,
           "fragments are not mistaken for UDP headers")

    six_req = request(int_attr(3, 6), port_attr(61000))
    six = bytearray(48 + len(six_req))
    six[0] = 0x60
    six[6] = 17
    six[7] = 64
    w16(six, 4, len(six) - 40)
    six[8:24] = mapped("10.0.0.2")
    six[24:40] = mapped("18.176.255.15")
    w16(six, 40, 56008)
    w16(six, 42, 3478)
    w16(six, 44, len(six) - 40)
    six[48:] = six_req
    six_reply = F.fabricate_ipv6(bytes(six), "203.0.113.1", 56008)
    expect(six_reply is not None, "ipv6 reply exists")
    expect(six_reply[8:24] == mapped("54.199.110.22"),
           "mapped IPv6 source obeys change IP")
    expect(u16(six_reply, 40) == 3479 and u16(six_reply, 42) == 61000,
           "mapped IPv6 response port directions")
    address(attributes(six_reply, 48)[0x802B],
            mapped("54.199.110.22"), 3479, 2)
    pseudo = six_reply[8:40] + struct.pack(">I", len(six_reply) - 40)
    pseudo = pseudo[:8] + bytes([0, 0, 0, 17])
    expect(checksum16(pseudo + six_reply[40:]) == 0xFFFF,
           "IPv6 UDP checksum")
    native = bytearray(six)
    native[24] = 0x20
    native[25] = 0x01
    expect(F.fabricate_ipv6(bytes(native), "203.0.113.1", 56008) is None,
           "unverified native IPv6 server uses normal path")
    print(f"PASS STUN regression matrix: {ASSERTIONS} assertions")


if __name__ == "__main__":
    verify_all()
