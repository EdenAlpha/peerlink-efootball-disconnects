#!/usr/bin/env python3
"""probe_shared_rendezvous.py -- do both identities have to share ONE rendezvous?

Run #36 established two DTLS sessions and held them all match, but reported
`received: 0` on both.  The reason is visible in its own logs: each identity
ran its own anonymous STUN Allocate, and the endpoint is issued PER ALLOCATE
(30317, 31794, 31542, 31803, 30532, 31471 across calls).  So the two bots were
never on the same relay, and neither was registered with anything.

The real client does not do this: the gate hands both clients the SAME
gamerelay for a match, and the capture's DTLS targets (30236, 30116, 30650,
30905, 30222) sit in the very same 30xxx range the TURN SOFTWARE string issues
today.  That says the rendezvous is per-MATCH and shared, not per-connection.

This opens two DTLS sessions against a single issued endpoint and reports
whether the server ever pushes back.

  python probe_shared_rendezvous.py
"""
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

import dtls_openssl as O                                         # noqa: E402
from dtls_hold import (rendezvous, PREAMBLE, PREAMBLE_GAP,     # noqa: E402
                       APPDATA, INTERVAL)


def run_two(host, port, ip, secs=20):
    """Two independent clients on ONE endpoint, both sending."""
    cs = []
    for tag in ("A", "B"):
        c = O.Dtls(host, port, ip)
        t0 = time.time()
        c.handshake(timeout=20)
        info = c.report()
        print("  client %s: %s %s handshake=%.3fs"
              % (tag, info["version"], info["cipher"], time.time() - t0))
        cs.append(c)

    rx = {"A": 0, "B": 0}
    tx = {"A": 0, "B": 0}
    end = time.time() + secs
    step = 0
    while time.time() < end:
        for tag, c in zip(("A", "B"), cs):
            n = PREAMBLE[step] if step < len(PREAMBLE) else APPDATA
            try:
                if c.send_appdata(b"\x00" * n):
                    tx[tag] += 1
            except Exception as e:                                # noqa: BLE001
                print("  %s send failed: %s" % (tag, e))
                return rx, tx
            try:
                got = c.recv_appdata(timeout=0.15)
                if got:
                    rx[tag] += 1
                    print("  << %s RECEIVED %dB: %s"
                          % (tag, len(got), got[:24].hex()))
            except Exception as e:                                # noqa: BLE001
                print("  %s recv failed: %s" % (tag, e))
        step += 1
        time.sleep(PREAMBLE_GAP if step <= len(PREAMBLE) else INTERVAL)
    return rx, tx


def main() -> int:
    print("=== one Allocate -> one shared rendezvous ===")
    host, port, ip, soft = rendezvous()
    print("  SOFTWARE %s" % soft)
    print("  -> %s:%d (%s)" % (host, port, ip))

    print("\n=== two DTLS clients on that endpoint (20 s) ===")
    try:
        rx, tx = run_two(host, port, ip)
    except Exception as e:                                        # noqa: BLE001
        print("  handshake failed: %s" % e)
        return 1
    print("\n  tx A=%d B=%d   rx A=%d B=%d" % (tx["A"], tx["B"],
                                              rx["A"], rx["B"]))
    if rx["A"] or rx["B"]:
        print("  -> SERVER PUSHES BACK on a shared endpoint")
        return 0
    print("  -> still silent; endpoint is shared but content matters")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
