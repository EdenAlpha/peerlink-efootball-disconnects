#!/usr/bin/env python3
"""p2p_stun.py -- bot-side STUN/RP speaker for eFootball's P2P UDP channel.

Wire facts pinned from the real-match capture (match-2026-09-26,
z1-tiamant-client/passthrough_capture.csv) and the Ghidra attribute tables:

  STUN header : [type:2 BE][len:2 BE][magic 0x2112A442][tid:12]
  method 0x20B: request 0x080B, response 0x090B (class bit 0x100)
  observed    : sole attribute RP_P2P_HEADER (0x9090), len 24 =
                b"\\x01\\x00\\x00\\x01" + b"\\x00"*4 + <own gate user_id,
                ASCII decimal, 16 bytes NUL-padded>
  semantics   : each side stamps its OWN user_id; a response echoes the
                request tid and carries the responder's id; unanswered
                requests are retransmitted with the SAME tid (~495 ms).

Self-test (loopback): python p2p_stun.py
"""
import os
import socket
import struct
import time

MAGIC = b"\x21\x12\xa4\x42"
REQ = 0x080B          # method 0x20B, class request
RES = 0x090B          # method 0x20B, class response
RP_P2P_HEADER = 0x9090
ATTR_NAMES = {0x9090: "RP_P2P_HEADER", 0x9091: "RP_RELIABILITY",
              0x9092: "RP_AMF_DATA", 0x9093: "RP_JSON_DATA",
              0x9094: "RP_HOST_ADDRESS", 0x9095: "RP_REFLEXIVE_ADDRESS",
              0x9096: "RP_RELAYED_ADDRESS", 0x9097: "RP_NAT_TYPE",
              0x9098: "RP_SYNC_POINT", 0x9099: "RP_ENTRY_IDX",
              0x909a: "RP_PEER_STATUS", 0x909b: "RP_RAND_SEED",
              0x909c: "RP_RELIABILITY_ECHO", 0x909d: "UHP_FINALIZE_RET",
              0x9999: "TERM", 0xf000: "ATTR_EXTENSION"}


def attr(code, value):
    pad = (-len(value)) % 4
    return struct.pack(">HH", code, len(value)) + value + b"\x00" * pad


def p2p_header(user_id):
    """24-byte RP_P2P_HEADER value: const prefix + 16-byte ASCII user_id."""
    s = str(user_id).encode()
    assert len(s) <= 16, "user_id must fit 16 ASCII bytes"
    return b"\x01\x00\x00\x01" + b"\x00" * 4 + s.ljust(16, b"\x00")


def build(mtype, tid, attrs=b""):
    assert len(tid) == 12
    return struct.pack(">HH", mtype, len(attrs)) + MAGIC + tid + attrs


def parse(buf):
    """-> (type, tid, [(code, value)]); raises ValueError on malformed."""
    if len(buf) < 20:
        raise ValueError("short message")
    mtype, ln = struct.unpack(">HH", buf[:4])
    if mtype & 0xC000:
        raise ValueError("not STUN (top bits)")
    if buf[4:8] != MAGIC:
        raise ValueError("bad magic cookie")
    if len(buf) < 20 + ln:
        raise ValueError("truncated (len=%d have=%d)" % (ln, len(buf)))
    tid = buf[8:20]
    attrs = []
    off = 20
    end = 20 + ln
    while off + 4 <= end:
        code, alen = struct.unpack(">HH", buf[off:off + 4])
        if off + 4 + alen > end:
            break                       # malformed attr: skip rest (game logs "Skip Attr")
        attrs.append((code, buf[off + 4:off + 4 + alen]))
        off += 4 + ((alen + 3) & ~3)
    return mtype, tid, attrs


def own_id(attrs):
    """Extract the stamped user_id from RP_P2P_HEADER attrs, or None."""
    for code, val in attrs:
        if code == RP_P2P_HEADER and len(val) >= 24:
            return val[8:24].rstrip(b"\x00").decode(errors="replace")
    return None


class Speaker:
    """One P2P endpoint: answers peer requests, originates its own,
    retransmits unanswered requests with the same tid."""

    RETRANSMIT_S = 0.495

    def __init__(self, user_id, bind=("127.0.0.1", 0)):
        self.user_id = str(user_id)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(bind)
        self.addr = self.sock.getsockname()
        self.peer = None                 # last peer seen
        self.peer_id = None              # learned from peer's messages
        self._pending = None             # (tid, msg, deadline)

    def send_req(self, dest):
        tid = os.urandom(12)
        msg = build(REQ, tid, attr(RP_P2P_HEADER, p2p_header(self.user_id)))
        self.sock.sendto(msg, dest)
        self._pending = (tid, msg, time.monotonic() + self.RETRANSMIT_S, dest)
        return tid

    def pump(self, timeout=0.05):
        """Poll the socket once. Returns event dicts:
           {"ev": "req", "src":, "tid":, "id":}  -- peer request, RES already sent
           {"ev": "res", "src":, "tid":, "id":}  -- response to our request
           None on idle/timeout.
        """
        now = time.monotonic()
        if self._pending and now >= self._pending[2]:
            tid, msg, _, dest = self._pending
            self.sock.sendto(msg, dest)          # retransmit, SAME tid
            self._pending = (tid, msg, now + self.RETRANSMIT_S, dest)
        self.sock.settimeout(timeout)
        try:
            buf, src = self.sock.recvfrom(2048)
        except socket.timeout:
            return None
        try:
            mtype, tid, attrs = parse(buf)
        except ValueError:
            return None                              # not ours; ignore
        self.peer = src
        pid = own_id(attrs)
        if pid:
            self.peer_id = pid
        if mtype == REQ:
            ans = build(RES, tid, attr(RP_P2P_HEADER,
                                        p2p_header(self.user_id)))
            self.sock.sendto(ans, src)
            return {"ev": "req", "src": src, "tid": tid.hex(), "id": pid}
        if mtype == RES:
            if self._pending and tid == self._pending[0]:
                self._pending = None                 # acknowledged
            return {"ev": "res", "src": src, "tid": tid.hex(), "id": pid}
        return {"ev": "other", "src": src, "tid": tid.hex(),
                "type": mtype, "id": pid}

    def close(self):
        self.sock.close()


def _selftest():
    a = Speaker(1500395919)
    b = Speaker(1012115771)
    ok = True

    # 1. A -> B request/response with id exchange
    a.send_req(b.addr)
    ev = None
    for _ in range(40):
        ev = b.pump(0.01)
        if ev:
            break
    assert ev and ev["ev"] == "req" and ev["id"] == "1500395919", ev
    ev = None
    for _ in range(40):
        ev = a.pump(0.01)
        if ev:
            break
    assert ev and ev["ev"] == "res" and ev["id"] == "1012115771", ev
    print("1. req/res + id exchange ok (peer_id learned:", a.peer_id, ")")

    # 2. B originates: B -> A
    b.send_req(a.addr)
    ev = None
    for _ in range(40):
        ev = a.pump(0.01)
        if ev:
            break
    assert ev and ev["ev"] == "req" and ev["id"] == "1012115771", ev
    print("2. reverse direction ok (a.peer_id:", a.peer_id, ")")

    # 3. retransmit: drop first request, speaker re-sends same tid
    c = Speaker(111)
    d = Speaker(222)
    c.send_req(d.addr)
    time.sleep(0.06)
    # drain one datagram from d and DISCARD (simulated loss)
    d.sock.settimeout(0.2)
    try:
        d.sock.recvfrom(2048)
    except socket.timeout:
        pass
    tid1 = c._pending[0]
    time.sleep(c.RETRANSMIT_S + 0.02)
    ev = None
    for _ in range(60):
        ev = c.pump(0.01)                 # pumps the retransmit out
        if c._pending is None:
            break
        d.pump(0.01)                      # d answers the retransmit
    assert c._pending is None, "retransmit not acknowledged"
    print("3. retransmit same-tid acknowledged ok")

    # 4. byte-exact shape of a request (compare against captured wire form)
    msg = build(REQ, b"\x11" * 12, attr(RP_P2P_HEADER, p2p_header(1500395919)))
    assert len(msg) == 48, len(msg)                    # 20 hdr + 28 attr
    assert msg[:2] == b"\x08\x0b" and msg[4:8] == MAGIC
    assert msg[20:22] == b"\x90\x90" and struct.unpack(">H", msg[22:24])[0] == 24
    assert msg[24:] == bytes.fromhex("0100000100000000") + b"1500395919".ljust(16, b"\x00")
    print("4. request bytes match captured wire form (48 B, header 24-value)")
    print("ALL OK")
    a.close(); b.close(); c.close(); d.close()
    return ok


if __name__ == "__main__":
    _selftest()
