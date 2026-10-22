#!/usr/bin/env python3
"""Fake game for the datapath smoke test (runs inside a network namespace).

Role a: sends real STUN shape (plain binding + CHANGE-IP) to a cluster
server, asserts the fabricated mapping, then punches phone B's fabricated
endpoint and checks the reply source. Role b: binds its port, waits for the
punch, sees phone A's fabricated endpoint, replies with its own, also runs
its own STUN check. Exit 0 == every assertion held.
"""
import socket
import struct
import sys
import zlib

ROLE = sys.argv[1]
FAB_SELF, FAB_PEER = ("197.210.53.1", "197.210.53.2")
SELF_PORT, PEER_PORT = (45001, 45002) if ROLE == "a" else (45002, 45001)
CLUSTER_IP, CLUSTER_ALT_IP = "54.248.105.235", "54.150.255.185"
COOKIE = b"\x21\x12\xa4\x42"


def die(msg):
    print(f"FAKE-{ROLE.upper()} FAIL: {msg}", flush=True)
    raise SystemExit(1)


def ok(msg):
    print(f"FAKE-{ROLE.upper()} OK: {msg}", flush=True)


def stun(flags):
    body = struct.pack(">BBH", 0, 3, 4) + struct.pack(">I", flags)
    head = struct.pack(">BBH", 0, 1, len(body)) + COOKIE + bytes(range(8, 20))
    return head + body, head[8:20]


def parse_resp(data, want_txid, fab_expected):
    if len(data) < 28:
        die(f"short resp {len(data)}")
    if (data[0] << 8) | data[1] != 0x0101:
        die(f"not binding success: {data[0:2].hex()}")
    if data[8:20] != want_txid:
        die("txid mismatch")
    pos = 20
    end = len(data)
    xor = None
    while pos + 4 <= end:
        t = (data[pos] << 8) | data[pos + 1]
        l = (data[pos + 2] << 8) | data[pos + 3]
        if t == 0x0020:
            xor = data[pos + 4:pos + 4 + l]
        pos += 4 + ((l + 3) // 4) * 4
    if xor is None:
        die("no XOR-MAPPED")
    port = struct.unpack(">H", xor[2:4])[0] ^ 0x2112
    ip4 = ".".join(str(xor[4 + i] ^ COOKIE[i]) for i in range(4))
    if (ip4, port) != fab_expected:
        die(f"XOR-MAPPED {ip4}:{port} != expected {fab_expected[0]}:"
            f"{fab_expected[1]}")


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", SELF_PORT))
    my_port = s.getsockname()[1]

    # 1) plain binding: answer must arrive FROM the real server we called,
    #    mapping us to (fab_self, my own port).
    req, txid = stun(flags=0)
    s.sendto(req, (CLUSTER_IP, 3478))
    s.settimeout(5)
    data, addr = s.recvfrom(2048)
    if addr[0] != CLUSTER_IP or addr[1] != 3478:
        die(f"resp src {addr} != {CLUSTER_IP}:3478")
    parse_resp(data, txid, (FAB_SELF, my_port))
    ok(f"binding answered from {addr[0]}:{addr[1]} mapped="
       f"{FAB_SELF}:{my_port}")

    # 2) CHANGE-IP: reply must come from the cluster partner server.
    req, txid = stun(flags=4)
    s.sendto(req, (CLUSTER_IP, 3478))
    data, addr = s.recvfrom(2048)
    if addr[0] != CLUSTER_ALT_IP:
        die(f"CHANGE-IP resp src {addr[0]} != partner {CLUSTER_ALT_IP}")
    ok(f"CHANGE-IP answered from partner {addr[0]}:{addr[1]}")

    if ROLE == "a":
        s.sendto(b"A-PUNCH-1", (FAB_PEER, PEER_PORT))
        data, addr = s.recvfrom(64)
        if addr != (FAB_PEER, PEER_PORT):
            die(f"punch reply src {addr} != ({FAB_PEER},{PEER_PORT})")
        if data != b"B-REPLY-1":
            die(f"punch reply payload {data!r}")
        ok(f"punch exchange A: saw peer as {addr[0]}:{addr[1]}")
    else:
        # 3) own check on the second cluster + socket mapping
        req, txid = stun(flags=0)
        s.sendto(req, ("18.176.255.15", 3478))
        data, addr = s.recvfrom(2048)
        if addr[0] != "18.176.255.15":
            die(f"resp src {addr[0]} != 18.176.255.15")

        data, addr = s.recvfrom(64)
        if addr != (FAB_PEER, PEER_PORT):
            die(f"punch from {addr} != ({FAB_PEER},{PEER_PORT})")
        s.sendto(b"B-REPLY-1", addr)
        ok(f"punch exchange B: saw peer as {addr[0]}:{addr[1]}")
    print(f"FAKE-{ROLE.upper()} PASS", flush=True)


if __name__ == "__main__":
    main()
