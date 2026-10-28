#!/usr/bin/env python3
"""Token-gated direct lab line to the android device (android-lab workflow).

Ops (all require token):
  GET  /state                              -> device state/model/uptime
  GET  /shot                               -> PNG screenshot
  POST /tap   {"x":..,"y":..,"ms":..}      -> tap (UI convenience)
  POST /run   {"cmd":"...","timeout":ms}   -> adb shell
  POST /put   {"path":"/data/local/tmp/x","b64":"..."}
  GET  /pull?path=/data/local/tmp/x        -> {ok, b64}

Bound to 127.0.0.1 only; the ingress is the outbound tunnel (cloudflared
quick tunnel).  The process is started with a scrubbed environment so a
leaked token cannot reach the runner's own credentials.
"""
import base64
import hmac
import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = os.environ.get("RELAY_TOKEN", "")
SER = os.environ.get("ADB_SERIAL", "127.0.0.1:5555")
ADB = ["adb", "-s", SER]
MAXOUT = 262144


def adb(*a, timeout=15, binary=False):
    try:
        r = subprocess.run(ADB + list(a), capture_output=True, timeout=timeout)
        if binary:
            return r.returncode, r.stdout
        return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _tok(self, q):
        t = q.get("token", [""])[0]
        return hmac.compare_digest(t, TOKEN)

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._tok(q):
            return self._json(403, {"ok": False, "err": "bad token"})
        if u.path == "/state":
            _, st = adb("get-state")
            _, mod = adb("shell", "getprop ro.product.model")
            _, up = adb("shell", "cat /proc/uptime")
            return self._json(200, {"ok": True, "state": st.strip(),
                                    "model": mod.strip(), "uptime": up.strip()})
        if u.path == "/shot":
            rc, png = adb("exec-out", "screencap", "-p", binary=True, timeout=60)
            self.send_response(200 if rc == 0 else 500)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(png)))
            self.end_headers()
            self.wfile.write(png)
            return
        if u.path == "/pull":
            p = q.get("path", [""])[0]
            rc, out = adb("exec-out", "sh", "-c",
                          "base64 '%s' | tr -d '\\n'" % p, timeout=300)
            if rc != 0 or len(out) > MAXOUT * 2:
                return self._json(500, {"ok": False, "err": out[:400]})
            return self._json(200, {"ok": True, "path": p, "b64": out.strip()})
        return self._json(404, {"ok": False})

    def do_POST(self):
        u = urlparse(self.path)
        j = self._body()
        tok_ok = (self._tok(parse_qs(u.query)) or
                  hmac.compare_digest(str(j.get("token", "")), TOKEN))
        if not tok_ok:
            return self._json(403, {"ok": False, "err": "bad token"})
        if u.path == "/tap":
            x, y = int(j.get("x", 0)), int(j.get("y", 0))
            ms = max(50, min(2000, int(j.get("ms", 120))))
            adb("shell", "input", "tap", str(x), str(y))
            time.sleep(ms / 1000.0)
            return self._json(200, {"ok": True, "x": x, "y": y})
        if u.path == "/run":
            cmd = str(j.get("cmd", ""))
            tmo = max(1000, min(600000, int(j.get("timeout", 60000)))) / 1000.0
            rc, out = adb("shell", cmd, timeout=tmo)
            return self._json(200, {"rc": rc, "out": out[:MAXOUT]})
        if u.path == "/fetch":
            url = str(j.get("url", ""))
            path = str(j.get("path", ""))
            if not url.startswith("https://") or not path.startswith("/"):
                return self._json(400, {"ok": False,
                                        "err": "https url and absolute path required"})
            rc = subprocess.run(["curl", "-fsSL", "--max-time", "600",
                                 "-o", "/tmp/fetch.bin", url],
                                capture_output=True, timeout=660)
            if rc.returncode != 0:
                return self._json(500, {"ok": False,
                                        "err": "curl rc=%d %s" % (
                                            rc.returncode,
                                            rc.stderr.decode("utf-8",
                                                             "replace")[:300])})
            size = os.path.getsize("/tmp/fetch.bin")
            rc2, out = adb("push", "/tmp/fetch.bin", path, timeout=600)
            if rc2 == 0:
                adb("shell", "chmod", "755", path)
            return self._json(200, {"ok": rc2 == 0, "bytes": size,
                                    "out": out[:300]})
        if u.path == "/put":
            path = str(j.get("path", ""))
            data = base64.b64decode(j.get("b64", ""))
            if not path.startswith("/") or len(data) > 64 * 1024 * 1024:
                return self._json(400, {"ok": False,
                                        "err": "bad path or too big"})
            with open("/tmp/put.bin", "wb") as f:
                f.write(data)
            rc, out = adb("push", "/tmp/put.bin", path, timeout=300)
            if rc == 0:
                adb("shell", "chmod", "755", path)
            return self._json(200, {"ok": rc == 0, "out": out[:400]})
        return self._json(404, {"ok": False})


if __name__ == "__main__":
    print("labrelay on 127.0.0.1:8000 serial=%s" % SER, flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8000), H).serve_forever()
