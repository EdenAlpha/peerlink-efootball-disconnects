"""Self-test for relay.py - no device, no network, no CI run.

Usage:  python3 kgs-login/live/test_relay.py     (exit 0 = all checks pass)

Covers the three things that must never regress:
  * a wrong token is refused on every endpoint (403)
  * /text refuses anything a shell could interpret, so `adb shell` cannot be
    reached through it
  * the tap log records WHAT was done, never the text that was typed (the
    run artifact is public)
"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request

HERE = tempfile.mkdtemp(prefix="relaytest-")
TAPS = os.path.join(HERE, "taps.log")
TOKEN = "a" * 36

os.environ["RELAY_TOKEN"] = TOKEN
_spec = importlib.util.spec_from_file_location(
    "relay", os.path.join(os.path.dirname(os.path.abspath(__file__)), "relay.py"))
relay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relay)
relay.TAPS = TAPS

CALLS = []


def fake_run(*args, timeout=30):
    CALLS.append(list(args))
    if "screencap" in args:
        return 0, b"\x89PNG\r\n\x1a\n fake"
    return 0, b""


relay.run = fake_run

srv = relay.HTTPServer(("127.0.0.1", 0), relay.H)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = "http://127.0.0.1:%d" % PORT
fails = []


def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + ("  " + extra if extra else ""))
    if not cond:
        fails.append(name)


def get(path, token=TOKEN):
    try:
        with urllib.request.urlopen("%s%s?token=%s" % (BASE, path, token)) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def post(path, body):
    req = urllib.request.Request("%s%s" % (BASE, path),
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


# --- state ---
rc, body = get("/state")
check("state ok with good token", rc == 200 and json.loads(body)["ok"] is True)

# --- tap ---
rc, body = post("/tap", {"token": TOKEN, "x": 500, "y": 700})
d = json.loads(body) if rc == 200 else {}
check("tap ok, returns dt_ms", rc == 200 and "dt_ms" in d)
check("tap issued as input swipe hold", any("swipe" in c for c in CALLS))
rc, _ = post("/tap", {"token": "wrong", "x": 500, "y": 700})
check("tap bad token -> 403", rc == 403)
rc, _ = post("/tap", {"token": TOKEN, "x": 99999, "y": 700})
check("tap out of range -> 403", rc == 403)

# --- text ---
CALLS.clear()
rc, body = post("/text", {"token": TOKEN, "s": "player.one+tag@example.com"})
d = json.loads(body) if rc == 200 else {}
check("text ok, returns dt_ms", rc == 200 and "dt_ms" in d)
check("text sent via input text", any(
    "text" in c and "player.one+tag@example.com" in " ".join(c) for c in CALLS))

CALLS.clear()
rc, _ = post("/text", {"token": TOKEN, "s": "Pass-w0rd!2026"})
check("dash/bang password accepted", rc == 200 and any(
    "Pass-w0rd!2026" in " ".join(c) for c in CALLS))

for bad in ["a; rm -rf /", "a$(id)", "a`id`", "a && b", "x" * 121, "",
            "#comment", "-abc", "a\nb", "a'b", 'a"b', "a<b>c", "a|b",
            "a(b)", "a*b", "a[1]", "a\\b", "a{1}", " a"]:
    rc, _ = post("/text", {"token": TOKEN, "s": bad})
    check("text %r refused" % bad, rc == 403)

CALLS.clear()
rc, _ = post("/text", {"token": TOKEN, "s": "hi there"})
check("space typed as %%s", rc == 200 and any(
    "hi%sthere" in " ".join(c) for c in CALLS))
rc, _ = post("/text", {"token": "wrong", "s": "abc"})
check("text bad token -> 403", rc == 403)

# --- shot / unknown ---
rc, body = get("/shot")
check("shot returns png", rc == 200 and body[:4] == b"\x89PNG")
rc, _ = get("/shot", token="nope")
check("shot bad token -> 403", rc == 403)
rc, _ = get("/exec")
check("unknown path -> 403", rc == 403)

# --- the log ---
with open(TAPS) as fh:
    log = fh.read()
check("taps.log written", "tap\t" in log and "shot\t" in log and "text\t" in log)
check("text logged by length only",
      "len=" in log and "player.one" not in log
      and "Pass-w0rd" not in log and "hi there" not in log)

srv.shutdown()
print("\n%d failed" % len(fails))
sys.exit(1 if fails else 0)
