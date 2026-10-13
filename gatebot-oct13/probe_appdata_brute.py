#!/usr/bin/env python3
"""probe_appdata_brute.py -- what makes the server answer?

capture_appdata.py established the shape of the real channel:

    server is purely reactive   unsolicited pushes 0/175
    client 143 B plaintext  ->  server 129 B   (463 sent, 113 answered)
    client 317 B            ->  server 167 B
    client 155/151          ->  server 149/153

Our 143-byte records of zeros get nothing back (run #36: received 0), so the
server parses the plaintext and drops what it cannot type-dispatch.  The reply
size looks constant, which suggests the header selects a reply rather than the
payload sizing it -- so the type field may be findable by sweep.

One DTLS session, many candidates, drain before each send so a late reply is
never attributed to the wrong candidate.

  python probe_appdata_brute.py                 byte-0 sweep at 143 B
  python probe_appdata_brute.py --sweep2        bytes 0..1
  python probe_appdata_brute.py --sweep3        framing candidates
  python probe_appdata_brute.py --size          size sweep, byte0=0
"""
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

import dtls_openssl as O                                         # noqa: E402
from dtls_hold import rendezvous                                 # noqa: E402

GCM = 24          # record overhead, so 143 plaintext -> 167 fragment
WAIT = 0.35       # capture: median 171 ms, mean 260 ms, max 752 ms


def drain(c, t=0.12):
    got = b""
    try:
        while True:
            b = c.recv_appdata(timeout=t)
            if not b:
                break
            got += b
            t = 0.05
    except Exception:                                            # noqa: BLE001
        pass
    return got


def probe(c, payload, label, wait=WAIT):
    """send one candidate, report any reply"""
    stale = drain(c, 0.05)
    if stale:
        print("  [drain cleared %dB before %s]" % (len(stale), label))
    try:
        n = c.send_appdata(payload)
    except Exception as e:                                        # noqa: BLE001
        print("  send failed on %s: %s" % (label, e))
        return None
    if not n or n <= 0:
        print("  SSL_write refused on %s (n=%s)" % (label, n))
        return None
    t0 = time.time()
    reply = b""
    while time.time() - t0 < wait:
        b = c.recv_appdata(timeout=0.1)
        if b:
            reply += b
            break
    if reply:
        print("  <<< REPLY to %-28s %dB  %s"
              % (label, len(reply), reply[:20].hex()))
    return reply


def main() -> int:
    mode = "byte0"
    for a in ("--sweep2", "--sweep3", "--size"):
        if a in sys.argv:
            mode = a[2:]

    host, port, ip, _soft = rendezvous()
    print("rendezvous %s:%d (%s)" % (host, port, ip))
    c = O.Dtls(host, port, ip)
    c.handshake(timeout=20)
    print("DTLS up: %s" % c.report()["cipher"])
    print("sweep mode: %s\n" % mode)

    hits = []
    try:
        if mode == "byte0":
            # 143-byte body, vary only the first byte: a type/dispatch field
            for i in range(256):
                p = bytes([i]) + bytes(142)
                r = probe(c, p, "byte0=%02x" % i)
                if r:
                    hits.append((i, r))
        elif mode == "sweep2":
            for i in range(0, 256, 4):          # coarse; refine on a hit
                for j in range(0, 256, 16):
                    p = bytes([i, j]) + bytes(141)
                    r = probe(c, p, "b0=%02x b1=%02x" % (i, j))
                    if r:
                        hits.append(((i, j), r))
        elif mode == "sweep3":
            cands = [
                ("len16be + type0", bytes([0x00, 0x8F]) + bytes(141)),
                ("len16le + type0", bytes([0x8F, 0x00]) + bytes(141)),
                ("len32be", bytes([0x00, 0x00, 0x00, 0x8F]) + bytes(139)),
                ("len8", bytes([143]) + bytes(142)),
                ("type0 len16", bytes([0x00, 0x00, 0x8F]) + bytes(140)),
                ("ascii PLNK", b"PLNK" + bytes(139)),
                ("ascii PES ", b"PES " + bytes(139)),
                ("ascii NTL ", b"NTL " + bytes(139)),
                ("00 pad", bytes(143)),
                ("ff pad", bytes([0xFF] * 143)),
                ("seq1", bytes([1]) + bytes(142)),
                ("type 0x01 hdr4", bytes([0x01, 0x00, 0x00, 0x00]) + bytes(139)),
                ("magic 0x50455331", b"PES1" + bytes(139)),
                ("hb ascii", b"HEARTBEAT" + bytes(134)),
                ("keepalive", b"KEEPALIVE" + bytes(134)),
            ]
            for lbl, p in cands:
                r = probe(c, p, lbl, wait=0.45)
                if r:
                    hits.append((lbl, r))
        elif mode == "size":
            for sz in (32, 46, 61, 70, 83, 107, 129, 143, 149, 151, 153,
                       155, 167, 171, 195, 317, 422):
                r = probe(c, bytes(sz), "size=%d zero" % sz, wait=0.45)
                if r:
                    hits.append((sz, r))
    finally:
        c.close()

    print("\n=== %d hits ===" % len(hits))
    for k, r in hits:
        print("  %-10s %dB %s" % (str(k), len(r), r[:24].hex()))
    if not hits:
        print("  none: the server ignored every candidate -- likely the\n"
              "  message carries a per-session token we do not have,\n"
              "  rather than a bare type byte.")
    return 0 if hits else 2


if __name__ == "__main__":
    raise SystemExit(main())
