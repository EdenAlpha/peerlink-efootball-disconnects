"""Dump every applilink.jp request verbatim: path, headers, body.

These are Konami account endpoints (login.php / regist.php /
checkLoginStatus.php) that the project never captured. print them in full so
the account flow can be read directly instead of inferred.
"""
import sys
from mitmproxy import io as mio
from mitmproxy.http import HTTPFlow

# Windows consoles are cp1252 and will die on arbitrary body bytes. Reconfigure
# stdout once, at import, so raw payloads can be printed verbatim.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
except AttributeError:
    pass

path = sys.argv[1] if len(sys.argv) > 1 else "flows.mitm"
only = sys.argv[2] if len(sys.argv) > 2 else "applilink"
r = mio.FlowReader(open(path, "rb"))

for f in r.stream():
    if not isinstance(f, HTTPFlow):
        continue
    if only not in f.request.pretty_host:
        continue
    req, res = f.request, f.response
    print("=" * 78)
    print("%s %s" % (req.method, req.path))
    print("HOST %s   status %s" % (req.pretty_host, res.status_code if res else "-"))
    print("-- request headers --")
    for k, v in req.headers.items(multi=True):
        print("   %s: %s" % (k, v[:220]))
    rb = req.raw_content or b""
    print("-- request body (%d B) --" % len(rb))
    if rb:
        print("   " + rb[:600].decode("latin-1").replace("\r", "\\r").replace("\n", "\\n"))
    if res:
        sb = res.raw_content or b""
        print("-- response (%d B) --" % len(sb))
        if sb:
            print("   " + sb[:600].decode("latin-1").replace("\r", "\\r").replace("\n", "\\n"))