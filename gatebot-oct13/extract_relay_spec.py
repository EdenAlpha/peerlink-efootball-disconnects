#!/usr/bin/env python3
"""extract_relay_spec.py -- build work/relay_spec.json from the holder log.

Reads the last RAW gamerelay line in lobby_hold.log, splits the comma
list (3 endpoints + token).  Prints ONLY redacted shapes.
"""
import json
import re

LOG = r"C:\Users\Administrator\Documents\Default Project\work\lobby_hold.log"
OUT = r"C:\Users\Administrator\Documents\Default Project\work\relay_spec.json"

line = None
with open(LOG, "r", encoding="utf-8", errors="replace") as f:
    for ln in f:
        if "RAW gamerelay:" in ln:
            line = ln.strip()
if not line:
    raise SystemExit("no RAW gamerelay line in log")

m = re.search(r"name='([^']*)'\s+region='([^']*)'\s+ip='([^']*)'\s+port=(\d+)",
              line)
if not m:
    raise SystemExit("parse failed")
name, region, ipfield, port = m.groups()
parts = ipfield.split(",")
if len(parts) != 4:
    raise SystemExit("expected 4 comma fields, got %d" % len(parts))
token = parts[3]
sid_m = re.search(r"/([0-9a-f]{32})/(\d+)$", name)
sid = sid_m.group(1) if sid_m else ""
side = sid_m.group(2) if sid_m else ""

spec = {
    "name": name,
    "sid": sid,
    "side": side,
    "token": token,
    "region": region,
    "endpoints": parts[:3],
    "port_field": int(port),
}
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(spec, f, indent=1)

print("relay_spec.json written (LOCAL ONLY):")
print("  name len=%d relay_instance=%s sid=%s... side=%s"
      % (len(name), name.split("/")[0], sid[:6] + "...", side))
print("  token len=%d endpoints=%s region=%s"
      % (len(token), [e.rsplit(":", 1)[0].split(".")[-1] + ":" +
                      e.rsplit(":", 1)[1] for e in parts[:3]], region))
