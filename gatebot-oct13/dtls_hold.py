#!/usr/bin/env python3
"""dtls_hold.py -- hold a live DTLS session to the Konami rendezvous for the
whole match.

Why this exists: POSTROOM_FLOW.md s23.16 eliminates every other candidate for
the server's liveness check (the STUN T7 beat, the pre-kickoff gate commands,
the bot-to-bot punch -- which Konami cannot even observe).  What is left is
the DTLS game channel to Konami's own Google-Cloud rendezvous, which chain3
has never opened.  The 2026-09-26 capture shows the real client sustaining it
with sub-1-pps client appdata records of ~167 B for the whole match.

Endpoint discovery is live and session-scoped:

  CMD_GET_TURN_SERVER_LIST {"turn_account_param":"","turn_time_limit":0}
    -> turn_server_list (TCP+TLS 443) + turn_account {id, pw}
  STUN Allocate over TLS -> 401 + NONCE
    -> SOFTWARE "ip:port,reversed-ip,0"   (a fresh port every attempt)
  DTLS 1.2 ECDHE cookie handshake to ip:port  -> hello_verify -> ESTABLISHED

Establishment is done by OpenSSL through dtls_openssl.py, so the cookie,
ECDHE, extended_master_secret and Finished computations are the reference
implementations rather than guesses about which messages enter the transcript.

  python dtls_hold.py                start one, hold 15 s, report
"""
import socket
import sys
import threading
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")

import dtls_openssl as O                                         # noqa: E402
import turn_rendezvous as TR                                     # noqa: E402

APPDATA = 143          # steady keepalive PLAINTEXT size
# The capture's records are 167 B *fragments*.  Subtracting the TLS-GCM
# per-record overhead (8 B explicit IV + 16 B auth tag) gives 143 B of
# plaintext, and 143 is the dominant plaintext in the capture: 463 of 591
# appdata records (78%).  Sending 167 B of plaintext -- the mistake here
# before this note -- produces a 191 B record, which no real record matches.
#
# Steady-state cadence measured on the capture's busiest flow
# (10.0.0.2:37135 -> 34.156.177.234:30236): median 1.00 s, mean 1.08 s,
# with a repeating ~0.11 s / ~1.1 s / ~3.8 s pattern.
INTERVAL = 1.0

# What the real client sends immediately after the handshake, sizes in
# plaintext bytes, spaced ~0.15 s apart, before it settles onto 143 B:
#   317, 107, 155, 155, 151, 151, 143  (fragments 341,131,179,179,175,175,167)
PREAMBLE = [317, 107, 155, 155, 151, 151]
PREAMBLE_GAP = 0.15


def rendezvous():
    """-> (host, port, ip, software).  Fresh every call."""
    mt, at = TR.allocate()
    soft = next((v for n, v, _ in at if n == "SOFTWARE"), "")
    if not soft:
        raise RuntimeError("TURN allocate gave no SOFTWARE (method 0x%04x)" % mt)
    host, _, port = soft.split(",")[0].rpartition(":")
    port = int(port)
    ip = socket.getaddrinfo(host, port, socket.AF_INET,
                            socket.SOCK_DGRAM)[0][4][0]
    return host, port, ip, soft


class DtlsHold:
    """One established session plus a keeper thread that keeps appdata
    flowing until stop()."""

    def __init__(self, tag, appdata=APPDATA, interval=INTERVAL):
        self.tag = tag
        self.appdata = appdata
        self.interval = interval
        self.client = None
        self.thread = None
        self.evt = threading.Event()
        self.sent = 0
        self.received = 0
        self.err = ""
        self.info = {}

    def start(self, timeout=25.0):
        host, port, ip, soft = rendezvous()
        self.info["endpoint"] = "%s:%d" % (host, port)
        self.info["ip"] = ip
        self.info["software"] = soft
        t0 = time.time()
        self.client = O.Dtls(host, port, ip)
        self.client.handshake(timeout=timeout)
        self.info.update(self.client.report())
        self.info["handshake_s"] = round(time.time() - t0, 3)
        self.evt = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True,
                                       name="dtls-%s" % self.tag.strip())
        self.thread.start()
        return self

    def _run(self):
        # preamble: the exact size sequence the real client opens with
        for n in PREAMBLE:
            if self.evt.is_set():
                break
            try:
                if self.client.send_appdata(b"\x00" * n):
                    self.sent += 1
            except Exception as e:                                # noqa: BLE001
                self.err = "preamble send %dB: %s" % (n, e)
                break
            self.evt.wait(PREAMBLE_GAP)
        # steady state: 143 B plaintext at ~1 Hz
        while not self.evt.wait(self.interval):
            try:
                n = self.client.send_appdata(b"\x00" * self.appdata)
                if n and n > 0:
                    self.sent += 1
            except Exception as e:                                # noqa: BLE001
                self.err = "send: %s" % e
                break
            try:
                got = self.client.recv_appdata(timeout=0.25)
                if got:
                    self.received += 1
            except Exception as e:                                # noqa: BLE001
                self.err = "recv: %s" % e

    def stop(self):
        self.evt.set()
        if self.thread:
            self.thread.join(timeout=3.0)
        try:
            if self.client:
                self.client.close()
        except Exception:                                         # noqa: BLE001
            pass
        self.info["sent"] = self.sent
        self.info["received"] = self.received
        if self.err:
            self.info["err"] = self.err
        return self.info


def _demo():
    print("=== dtls_hold demo ===")
    h = DtlsHold("demo")
    try:
        h.start()
    except Exception as e:                                        # noqa: BLE001
        print("  handshake failed: %s" % e)
        return 1
    print("  established: %s" % {k: v for k, v in h.info.items()
                                 if k in ("endpoint", "version", "cipher",
                                          "handshake_s", "verify_result")})
    print("  holding 15s ...")
    time.sleep(15)
    print("  %s" % h.stop())
    return 0


if __name__ == "__main__":
    raise SystemExit(_demo())
