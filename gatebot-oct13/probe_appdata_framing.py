#!/usr/bin/env python3
"""probe_appdata_framing.py -- is the 143 B heartbeat just length-prefixed?

probe_appdata_brute.py swept the FIRST byte of a 143-byte body and got 0
hits, concluding the message carries a per-session token.  That conclusion
assumed the dispatch field sits at offset 0.  If the frame is length-prefixed
instead, every candidate it sent carried a garbage length, so the server
dropped the record before reading a type -- the sweep could not have
succeeded whatever the type was.

capture_appdata.py shows what we are trying to satisfy:

    client 143 B plaintext -> server 129 B   (463 sent, 113 answered)
    server unsolicited pushes: 0/175
    client -> server response latency: median 171 ms, mean 260 ms

so the reply size is fixed per request size, which is what a length-prefixed
frame with a type dispatch would look like.

PACING (the first attempt timed out at 900 s and lost its output):
dtls_openssl._pump() ignores its ``wait`` argument and calls recvfrom with
whatever the socket timeout is -- set to 0.5 s in Dtls.__init__.  So every
recv_appdata() costs >= 0.5 s even when asked for 0.04 s, i.e. ~1 s per
candidate x 1024 = ~1100 s.  The sweep sets its own socket timeout instead:
a short one to drain leftovers cheaply, then ~0.45 s to catch a reply whose
median latency is 171 ms.

  python -u probe_appdata_framing.py
"""
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

import dtls_openssl as O                                         # noqa: E402
from dtls_hold import rendezvous                                 # noqa: E402

DRAIN_TO = 0.03      # socket timeout used only to discard stale replies
REPLY_TO = 0.45      # > the capture's 171 ms median / 260 ms mean
N = 143              # steady-state plaintext size


def drain(c, sock_to=DRAIN_TO, call_to=0.06):
    """Discard anything already pending, cheaply (one short recvfrom)."""
    c.sock.settimeout(sock_to)
    got = b""
    try:
        got = c.recv_appdata(timeout=call_to)
    except Exception:                                            # noqa: BLE001
        pass
    return got


# (label, framing taking a type byte -> full N-byte payload)
FRAMINGS = [
    ("len32be type@4",
     lambda t: (N - 5).to_bytes(4, "big") + bytes([t]) + bytes(N - 5)),
    ("len16be type@2",
     lambda t: (N - 3).to_bytes(2, "big") + bytes([t]) + bytes(N - 3)),
    ("len16be==143 type@2",
     lambda t: N.to_bytes(2, "big") + bytes([t]) + bytes(N - 3)),
    ("type@0 len16be@1",
     lambda t: bytes([t]) + (N - 3).to_bytes(2, "big") + bytes(N - 3)),
]


def main() -> int:
    fw = FRAMINGS[:2] if "--fast" in sys.argv else FRAMINGS

    host, port, ip, _soft = rendezvous()
    print("rendezvous %s:%d (%s)" % (host, port, ip), flush=True)
    c = O.Dtls(host, port, ip)
    c.handshake(timeout=20)
    print("DTLS up: %s" % c.report()["cipher"], flush=True)
    # keep handshake pacing intact; the sweep sets its own per-call timeout
    t_start = time.time()

    hits = []
    tried = 0
    try:
        for fi, (name, fmt) in enumerate(fw):
            print("\n=== %s (%d/%d) ===" % (name, fi + 1, len(fw)), flush=True)
            got_this = 0
            for t in range(256):
                stale = drain(c)
                if stale:
                    print("  [cleared %dB]" % len(stale), flush=True)
                c.sock.settimeout(REPLY_TO)
                try:
                    n = c.send_appdata(fmt(t))
                except Exception as e:                            # noqa: BLE001
                    print("  send failed t=%02x: %s" % (t, e), flush=True)
                    break
                if not n or n <= 0:
                    print("  SSL_write refused at t=%02x" % t, flush=True)
                    break
                tried += 1
                r = c.recv_appdata(timeout=REPLY_TO + 0.05)
                if r:
                    print("  <<< REPLY type=%02x %dB %s"
                          % (t, len(r), r[:24].hex()), flush=True)
                    hits.append((name, t, r))
                    got_this += 1
                elif t % 64 == 0:
                    print("    ...t=%03d  %.0fs elapsed"
                          % (t, time.time() - t_start), flush=True)
            print("  -> %d replies in 256 types (%.0fs)"
                  % (got_this, time.time() - t_start), flush=True)
    finally:
        try:
            c.close()
        except Exception:                                        # noqa: BLE001
            pass

    print("\n=== %d/%d candidates answered in %.0fs ==="
          % (len(hits), tried, time.time() - t_start), flush=True)
    for name, t, r in hits:
        print("  %-20s type=%02x %dB %s" % (name, t, len(r), r[:24].hex()))
    if not hits:
        print("  none.  Length framing at these offsets is not it either --\n"
              "  the next step is the binary, not more guessing.")
    return 0 if hits else 2


if __name__ == "__main__":
    raise SystemExit(main())
