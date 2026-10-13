#!/usr/bin/env python3
"""dtls_live.py -- complete the DTLS cookie exchange against the live
rendezvous issued by the Konami TURN server.

Discovery chain (all live, 2026-10-13):

  CMD_GET_TURN_SERVER_LIST {"turn_account_param":"","turn_time_limit":0}
    -> 132.8.211.130.bc.googleusercontent.com:443   (in-room, after
       CMD_GET_GAME_SESSION; NOERR)
  TCP+TLS 443 to 130.211.8.132 (NOT 5349 -- that port is closed)
    -> STUN Allocate -> 401 Unauthorized + NONCE + REALM ''
       SOFTWARE = "34.182.219.64:31794,64.219.182.34.bc...,0"
       (issued per attempt -- that is why capture-era ports are dead)
  DTLS ClientHello to ip:port
    -> hello_verify_request (verified 2 ms)

This script walks the exchange one flight at a time and prints exactly what
the server says, so the cipher suite / cert chain / extensions are learned
from the wire rather than guessed.  The client hello is the capture's OWN
bytes with only the cookie field rewritten, so the server sees the same
flight the real phone sent.

  python dtls_live.py                 cookie exchange + server flight
  python dtls_live.py --raw           hex-dump every record
"""
import socket
import ssl
import struct
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
import replay_clienthello as R                                     # noqa: E402

TURN_HOST, TURN_PORT, SNI = "130.211.8.132", 443, "pes20.turn.konami.com"
TXID = bytes.fromhex("0a0b0c0d0e0f101112131415")

HSN = {0: "hello_request", 1: "client_hello", 2: "server_hello",
       3: "hello_verify", 4: "new_session_ticket", 11: "certificate",
       12: "server_key_exchange", 13: "certificate_request",
       14: "server_hello_done", 15: "certificate_verify",
       16: "client_key_exchange", 20: "finished"}
CIPHERS = {0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
           0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
           0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
           0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
           0xC013: "ECDHE-RSA-AES128-CBC-SHA",
           0xC014: "ECDHE-RSA-AES256-CBC-SHA",
           0xC009: "ECDHE-ECDSA-AES128-CBC-SHA",
           0xC00A: "ECDHE-ECDSA-AES256-CBC-SHA",
           0x002F: "AES128-SHA", 0x0035: "AES256-SHA"}
EXTH = {0: "server_name", 10: "supported_groups", 11: "ec_point_formats",
        13: "signature_algorithms", 16: "alpn", 18: "signed_cert_ts",
        23: "extended_master_secret", 65281: "renegotiation_info",
        0xff01: "renegotiation_info"}


def tls_alloc():
    ss = None
    raw = socket.create_connection((TURN_HOST, TURN_PORT), timeout=6)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(raw, server_hostname=SNI)
    ss.settimeout(6)
    return ss


def get_rendezvous():
    """-> (ip, port, software_string).  Fresh each call: the port is issued
    per Allocate."""
    ss = tls_alloc()
    ss.sendall(struct.pack("!HHI", 0x0003, 0, 0x2112A442) + TXID)
    d = ss.recv(4096)
    ss.close()
    soft = ""
    if len(d) >= 20:
        ml = struct.unpack("!H", d[2:4])[0]
        i = 20
        while i + 4 <= min(20 + ml, len(d)):
            at, al = struct.unpack("!HH", d[i:i + 4])
            v = d[i + 4:i + 4 + al]
            if at == 0x8022:
                soft = v.decode("utf-8", "replace")
            i += 4 + al + (4 - (al % 4)) % 4
    if not soft:
        raise RuntimeError("no SOFTWARE attribute: %d B" % len(d))
    host, _, port = soft.split(",")[0].rpartition(":")
    return host, int(port), soft


def parse_hs_body(b):
    """ClientHello body -> dict of fields (so we can rewrite only cookie)."""
    i = 0
    ver = struct.unpack("!H", b[i:i + 2])[0]; i += 2
    rnd = b[i:i + 32]; i += 32
    sl = b[i]; i += 1
    sid = b[i:i + sl]; i += sl
    cl = b[i]; i += 1
    cookie = b[i:i + cl]; i += cl
    cs = b[i:i + 2]; i += 2
    suites = b[i:i + struct.unpack("!H", cs)[0]]; i += struct.unpack("!H", cs)[0]
    clen = b[i]; i += 1
    comp = b[i:i + clen]; i += clen
    el = b[i:i + 2]; i += 2
    ext = b[i:i + struct.unpack("!H", el)[0]]
    return dict(ver=ver, rnd=rnd, sid=sid, cookie=cookie,
                suites=suites, comp=comp, ext=ext)


def build_ch(f, recver=0xFEFF, mseq=0, rseq=0):
    """Rebuild a ClientHello.  Three things must be right or the server drops
    the datagram without a word:

      record header version  = 0xfeff   (DTLS 1.0, the cookie-probe flight)
      ClientHello body ver   = 0xfefd   (the version the handshake claims)
      record seq + hs message_seq       -- flight 2 uses 1/1, NOT 0/0: the
        server has already consumed message_seq 0 for the cookie probe and
        silently discards a repeat.  (Capture CH0: seq=0/mseq=0,
        CH1: seq=1/mseq=1.)

    The DTLS handshake header is 12 bytes: type(1) + length(3) +
    message_seq(2) + fragment_offset(3) + fragment_length(3)."""
    body = (struct.pack("!H", f["ver"]) + f["rnd"]
            + bytes([len(f["sid"])]) + f["sid"]
            + bytes([len(f["cookie"])]) + f["cookie"]
            + struct.pack("!H", len(f["suites"])) + f["suites"]
            + bytes([len(f["comp"])]) + f["comp"]
            + struct.pack("!H", len(f["ext"])) + f["ext"])
    hs = (b"\x01" + len(body).to_bytes(3, "big")     # client_hello + length
          + struct.pack("!H", mseq)                  # message_seq
          + b"\x00" * 3                              # fragment_offset
          + len(body).to_bytes(3, "big")             # fragment_length
          + body)
    return (b"\x16" + struct.pack("!H", recver) + b"\x00\x00"
            + int(rseq).to_bytes(6, "big")
            + struct.pack("!H", len(hs)) + hs)


def parse_records(buf):
    out, i = [], 0
    while i + 13 <= len(buf):
        ct = buf[i]
        ver = struct.unpack("!H", buf[i + 1:i + 3])[0]
        ep = struct.unpack("!H", buf[i + 3:i + 5])[0]
        seq = int.from_bytes(buf[i + 5:i + 11], "big")
        ln = struct.unpack("!H", buf[i + 11:i + 13])[0]
        if i + 13 + ln > len(buf):
            break
        out.append((ct, ver, ep, seq, buf[i + 13:i + 13 + ln]))
        i += 13 + ln
    return out, buf[i:]


def parse_handshakes(records):
    """Reassemble DTLS handshake messages from fragments."""
    frags = {}
    for ct, ver, ep, seq, body in records:
        if ct != 0x16 or len(body) < 12:
            continue
        mt = body[0]
        ln = int.from_bytes(body[1:4], "big")
        mseq = struct.unpack("!H", body[4:6])[0]
        off = int.from_bytes(body[6:9], "big")
        fln = int.from_bytes(body[9:12], "big")
        d = frags.setdefault((mt, mseq), bytearray(ln))
        d[off:off + fln] = body[12:12 + fln]
    return [(k[0], k[1], bytes(v)) for k, v in frags.items()]


def show_hs(items, raw=False):
    for mt, mseq, body in items:
        name = HSN.get(mt, "hs%d" % mt)
        print("    %-22s seq=%d len=%d" % (name, mseq, len(body)))
        if mt == 2 and len(body) >= 38:                       # server_hello
            ver = struct.unpack("!H", body[:2])[0]
            sidlen = body[34]
            i = 35 + sidlen
            cs = struct.unpack("!H", body[i:i + 2])[0]
            comp = body[i + 2]
            print("        ver=0x%04x cipher=0x%04x (%s) comp=%d"
                  % (ver, cs, CIPHERS.get(cs, "unknown"), comp))
            j = i + 3
            if j + 2 <= len(body):
                el = struct.unpack("!H", body[j:j + 2])[0]
                j += 2
                end = j + el
                while j + 4 <= end:
                    et, eL = struct.unpack("!HH", body[j:j + 4])
                    print("        ext %d (%s) %dB"
                          % (et, EXTH.get(et, "?"), eL))
                    j += 4 + eL
        if mt == 3 and len(body) >= 3:                        # hello_verify
            ver = struct.unpack("!H", body[:2])[0]
            cl = body[2]
            print("        ver=0x%04x cookie=%dB" % (ver, cl))
        if mt == 11:                                          # certificate
            print("        cert chain, total %dB" % len(body))
        if mt == 12 and len(body) >= 4:
            print("        keyx %dB" % len(body))
        if raw:
            print("        %s" % body[:64].hex())


def captured_ch():
    """The real phone's first flight, verbatim."""
    for key, pkts in R.load_capture().items():
        if not (30000 <= key[3] <= 33000):
            continue
        for d, pl in pkts:
            if d == "t" and pl[:1] == b"\x16":
                return pl
    return None


def main() -> int:
    raw = "--raw" in sys.argv
    host, port, soft = get_rendezvous()
    print("rendezvous  %s:%d" % (host, port))
    print("  SOFTWARE  %s" % soft)
    ip = socket.getaddrinfo(host, port, socket.AF_INET,
                            socket.SOCK_DGRAM)[0][4][0]
    print("  resolved  %s" % ip)

    ch = captured_ch()
    if not ch:
        print("  no captured ClientHello")
        return 1
    recs, _ = parse_records(ch)
    recver = recs[0][1]
    items = parse_handshakes(recs)
    _, _, body = items[0]
    fields = parse_hs_body(body)

    # self-test: an empty-cookie rebuild must be byte-identical to the
    # capture.  If it is not, the server will silently drop flight 2.
    probe_f = dict(fields, cookie=b"")
    same = build_ch(probe_f, recver) == ch
    print("\nrebuild self-test vs capture: %s" % ("OK" if same else "MISMATCH"))
    if not same:
        print("  -> aborting, rebuild does not reproduce the real flight")
        return 1

    print("\ncaptured ClientHello: %dB  suites=%dB  ext=%dB  cookie=%dB"
          % (len(ch), len(fields["suites"]), len(fields["ext"]),
             len(fields["cookie"])))
    print("  offered ciphers: %s"
          % ", ".join(CIPHERS.get(struct.unpack("!H", fields["suites"][i:i + 2])[0],
                                  "0x%04x" % struct.unpack(
                                      "!H", fields["suites"][i:i + 2])[0])
                      for i in range(0, len(fields["suites"]), 2)))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(6)
    t0 = time.time()
    s.sendto(ch, (ip, port))
    d, frm = s.recvfrom(4096)
    print("\nflight 1 -> %dB from %s:%d (%dms)"
          % (len(d), frm[0], frm[1], int((time.time() - t0) * 1000)))
    recs, _ = parse_records(d)
    items = parse_handshakes(recs)
    show_hs(items, raw)

    cookie = None
    for mt, _mseq, b in items:
        if mt == 3 and len(b) >= 3:
            cookie = b[3:]
    if not cookie:
        print("  no cookie -> abort")
        s.close()
        return 1
    print("  cookie = %dB" % len(cookie))

    fields["cookie"] = cookie
    ch2 = build_ch(fields, recver, mseq=1, rseq=1)
    print("\nflight 2 = %dB (ClientHello + cookie)" % len(ch2))

    # verify we really did insert the cookie the way the server will read it
    recs2, _ = parse_records(ch2)
    _f2 = parse_hs_body(parse_handshakes(recs2)[0][2])
    print("  echo-check: cookie %dB round-trips as %dB, matches: %s"
          % (len(cookie), len(_f2["cookie"]), _f2["cookie"] == cookie))

    # DTLS is datagram-oriented: retransmit until answered, as a real stack
    # would.  A single flight is routinely lost or silently dropped.
    got = b""
    frm = None
    t_start = time.time()
    for attempt in range(5):
        s.sendto(ch2, (ip, port))
        s.settimeout(0.8)
        while True:
            try:
                d, frm = s.recvfrom(8192)
            except socket.timeout:
                break
            got += d
        if got:
            print("  answered on attempt %d after %dms"
                  % (attempt + 1, int((time.time() - t_start) * 1000)))
            break
        time.sleep(0.5)
    s.close()
    if not got:
        print("  received 0B after %d attempts (%.1fs)"
              % (5, time.time() - t_start))
        return 0
    print("  received %dB from %s:%d" % (len(got), frm[0], frm[1]))
    recs, _ = parse_records(got)
    print("  %d record(s)" % len(recs))
    for ct, ver, ep, seq, body in recs:
        print("    type=0x%02x ver=0x%04x epoch=%d len=%d"
              % (ct, ver, ep, len(body)))
    items = parse_handshakes(recs)
    show_hs(items, raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
