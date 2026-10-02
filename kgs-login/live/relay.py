#!/usr/bin/env python3
"""Token-gated relay: near-real-time phone control through an outbound tunnel.

Why this exists: the git-branch command channel costs 60-120s per round trip.
This relay runs on the runner, talks to the phone over local adb, and is
exposed through an OUTBOUND tunnel (bore / cloudflared quick tunnel), so taps
land in ~1s from anywhere.

Security (non-negotiable):
  * Binds 127.0.0.1 ONLY. The only ingress is the tunnel, started explicitly.
  * Every request must carry the token (from $RELAY_TOKEN, staged as a GitHub
    secret, never committed). Compared with hmac.compare_digest.
  * Raw adb/shell is NEVER exposed. Exactly three operations exist:
      POST /tap   {token, x, y, ms?}  -> 250ms-hold tap, returns {ok, dt_ms}
      GET  /shot?token=...            -> PNG screenshot bytes
      GET  /state?token=...           -> {pid, focus, flows}
  * No shell passthrough, no file access, no command execution. Anything else
    still goes through the audited git channel.

Self-test (no device needed): test_relay.py pattern - fake adb on PATH,
check state/tap with good token and 403 with bad token. Verified 2026-10-02:
state ok, bad token -> 403, tap ok.
"""
import hmac
import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = os.environ.get("RELAY_TOKEN", "")
ADB = ["adb", "-s", "127.0.0.1:5555"]
FLOWS = "/tmp/kgs/flows.log"


def run(*args, timeout=30):
    try:
        r = subprocess.run(list(args), capture_output=True, timeout=timeout)
        return r.returncode, r.stdout
    except Exception as e:
        return -1, str(e).encode()


def ok200(handler, body=b'{"ok":true}', ctype="application/json"):
    handler.send_response(200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def deny(handler):
    handler.send_response(403)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


class H(BaseHTTPRequestHandler):
    server_version = "relay"

    def log_message(self, *a):
        pass

    def _token_ok(self, token):
        if not TOKEN or not token:
            return False
        return hmac.compare_digest(token, TOKEN)

    def do_POST(self):
        if self.path != "/tap":
            return deny(self)
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return deny(self)
        if not self._token_ok(req.get("token", "")):
            return deny(self)
        try:
            x, y, ms = int(req["x"]), int(req["y"]), int(req.get("ms", 250))
        except Exception:
            return deny(self)
        if not (0 <= x <= 2000 and 0 <= y <= 2000 and 50 <= ms <= 2000):
            return deny(self)
        t = time.time()
        run(*(ADB + ["shell", "input", "swipe",
                      str(x), str(y), str(x), str(y), str(ms)]))
        dt = int((time.time() - t) * 1000)
        ok200(self, ('{"ok":true,"dt_ms":%d}' % dt).encode())

    def do_GET(self):
        u = urlparse(self.path)
        token = parse_qs(u.query).get("token", [""])[0]
        if not self._token_ok(token):
            return deny(self)
        if u.path == "/shot":
            rc, png = run(*(ADB + ["exec-out", "screencap", "-p"]), timeout=30)
            if rc != 0 or png[:4] != b"\x89PNG":
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            ok200(self, png, "image/png")
        elif u.path == "/state":
            _, pid = run(*(ADB + ["shell", "pidof", "jp.konami.pesam"]))
            _, foc = run(*(ADB + ["shell", "dumpsys", "window"]))
            foc = [l for l in foc.decode("latin-1").splitlines() if "mCurrentFocus" in l]
            try:
                with open(FLOWS, errors="replace") as fh:
                    flows = sum(1 for l in fh if l.startswith("### "))
            except OSError:
                flows = 0
            ok200(self, json.dumps({
                "ok": True,
                "pid": pid.decode("latin-1").strip(),
                "focus": (foc[0].strip() if foc else ""),
                "flows": flows,
            }).encode())
        else:
            return deny(self)


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("RELAY_TOKEN is empty, refusing to start")
    srv = HTTPServer(("127.0.0.1", 8000), H)
    print("relay on 127.0.0.1:8000", flush=True)
    srv.serve_forever()
