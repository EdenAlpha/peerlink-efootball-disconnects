#!/usr/bin/env python3
"""beat_stream.py -- hold ONE gRPC stream open and beat every 15 seconds.

Mirrors the real game (pass-through capture, match-2026-09-26):
  * one TLS+h2 connection to pes22-game.cs.konami.net:443, ALPN grpc-exp
  * one CommandStream, never half-closed
  * a beat roughly every 15.0 s for the whole match

The dispatch key, found 2026-10-10 (grpc_beat.py): CommandRequest.id =
the command name, path = "/", packMode = 0 (JSON).  packMode 1 -> 14
UNAVAILABLE on every path, which is why every pre-2026-10-09 sweep that
used msgpack came back empty.

  python beat_stream.py            offline check
  python beat_stream.py --live     login, hold the stream, beat for --secs
  python beat_stream.py --live --secs 50 --interval 15
"""
from __future__ import annotations

import json
import socket
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import Gate, describe, login, load_capture  # noqa: E402

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\peerlink-efootball-disconnects\kgs-login\scripts")
import kgs_client as kc  # noqa: E402


class BeatStream:
    """One keep-open CommandStream.  Beats in-band; drains responses."""

    def __init__(self, g: Gate, interval: float = 15.0):
        self.g = g
        self.interval = interval
        self.sock = None
        self.buf = b""
        self.beats = 0
        self.replies = 0
        self.dead = ""
        env = g.envelope("CMD_HEARTBEAT_GRPC")
        env["heartbeat_interval_msec"] = int(interval * 1000)
        self.payload = json.dumps({k: v for k, v in env.items()
                                   if k != "msgid"}).encode()

    def open(self) -> bool:
        try:
            self.sock = kc.connect()          # preface + SETTINGS + HEADERS
        except Exception as e:                # noqa: BLE001
            self.dead = "connect: %s" % e
            return False
        return True

    def beat(self) -> None:
        msg = kc.command_request("CMD_HEARTBEAT_GRPC", "/",
                                 self.payload.decode(), kc.PACK_JSON)
        g = b"\x00" + len(msg).to_bytes(4, "big") + msg
        try:
            self.sock.sendall(kc.frame(0, 0x0, 1, g))   # DATA, stream open
            self.beats += 1
        except Exception as e:                # noqa: BLE001
            self.dead = "send: %s" % e

    def drain(self, seconds: float) -> None:
        """Read whatever the server sends for `seconds` (non-fatal)."""
        end = time.time() + seconds
        self.sock.settimeout(0.5)
        while time.time() < end and not self.dead:
            try:
                c = self.sock.recv(32768)
            except socket.timeout:
                continue
            except Exception as e:            # noqa: BLE001
                self.dead = "recv: %s" % e
                break
            if not c:
                self.dead = "server closed"
                break
            self.buf += c
            self._frames()

    def _frames(self) -> None:
        while len(self.buf) >= 9:
            ln = int.from_bytes(self.buf[0:3], "big")
            typ, flags = self.buf[3], self.buf[4]
            if len(self.buf) < 9 + ln:
                return
            body = self.buf[9:9 + ln]
            self.buf = self.buf[9 + ln:]
            if typ == 0 and body:                       # DATA
                i = 0
                while i + 5 <= len(body):
                    mlen = int.from_bytes(body[i + 1:i + 5], "big")
                    if i + 5 + mlen > len(body):
                        break
                    dec = kc.command_response(body[i + 5:i + 5 + mlen])
                    self.replies += 1
                    res = dec.get("res")
                    if isinstance(res, (dict, list)):
                        res = json.dumps(res, ensure_ascii=False)[:600]
                    print("    << beat reply: disp=%r res=%r"
                          % (dec.get("id"), (res or "")[:600]),
                          flush=True)
                    i += 5 + mlen
            elif typ == 1 and (flags & 0x1):            # HEADERS + END_STREAM
                self.dead = "stream ended by server"

    def run(self, secs: float) -> None:
        if self.sock is None and not self.open():
            print("  stream open FAILED: %s" % self.dead)
            return
        print("  stream open, beating every %.0fs for %.0fs"
              % (self.interval, secs), flush=True)
        next_beat = 0.0
        end = time.time() + secs
        while time.time() < end and not self.dead:
            now = time.time()
            if now >= next_beat:
                self.beat()
                print("  >> beat %d at t+%.1fs"
                      % (self.beats, secs - (end - now)), flush=True)
                next_beat = now + self.interval
            self.drain(min(0.5, max(0.0, next_beat - time.time())))
        try:
            self.sock.close()
        except Exception:                              # noqa: BLE001
            pass
        print("  done: beats=%d replies=%d%s"
              % (self.beats, self.replies,
                 (" dead=" + self.dead) if self.dead else ""))


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0
    secs = 50.0
    interval = 15.0
    for i, a in enumerate(sys.argv):
        if a == "--secs" and i + 1 < len(sys.argv):
            secs = float(sys.argv[i + 1])
        if a == "--interval" and i + 1 < len(sys.argv):
            interval = float(sys.argv[i + 1])

    reqs = load_capture()[0]
    g = Gate()
    ok, r = login(g, reqs)
    print("login        -> %s" % (r.get("result") if ok else describe(r)))
    if not ok:
        return 1
    BeatStream(g, interval).run(secs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
