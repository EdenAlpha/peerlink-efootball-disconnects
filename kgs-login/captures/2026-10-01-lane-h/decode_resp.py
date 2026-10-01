"""Decode every captured KGS response as MessagePack.

The bodies were recorded as unreadable hex for the whole project. This is the
test: if they are MessagePack, they were never encrypted and the "app-layer
AES-256" story is wrong for responses.
"""
import sys
from mitmproxy import io as mio
from mitmproxy.http import HTTPFlow

try:
    import msgpack
except ImportError:
    print("need msgpack: pip install msgpack")
    sys.exit(1)

path = sys.argv[1] if len(sys.argv) > 1 else "flows.mitm"
r = mio.FlowReader(open(path, "rb"))

for f in r.stream():
    if not isinstance(f, HTTPFlow) or not f.response:
        continue
    name = f.request.path.split("/")[-1][:44]
    body = f.response.raw_content or b""
    if not body:
        print("%-46s len=%-6d EMPTY" % (name, 0))
        continue
    try:
        obj = msgpack.unpackb(body, raw=False)
        kind = type(obj).__name__
        detail = ""
        if isinstance(obj, dict):
            detail = " keys=" + str(list(obj.keys())[:8])
        elif isinstance(obj, list):
            detail = " n=%d first=%r" % (len(obj), obj[0] if obj else None)
        else:
            detail = " val=" + repr(obj)[:80]
        print("%-46s len=%-6d MSGPACK %s%s" % (name, len(body), kind, detail))
    except Exception as e:
        print("%-46s len=%-6d not-msgpack (%s) first8=%s"
              % (name, len(body), str(e)[:40], body[:8].hex()))