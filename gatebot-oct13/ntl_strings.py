#!/usr/bin/env python3
"""ntl_strings.py -- extract the PeerLink/NTL (NAT-traversal lobby) protocol
vocabulary + HTTP endpoints from libUE4.so.

Line 17107/17856 revealed: http://ntl.service.konami.net/ntl/api/GateInfo.php,
CmdSendTurnAddressData.php, and a TURN/STUN/hole-punch state machine.  Pull the
contiguous string region around those anchors to map the full protocol: which
PHP endpoints exist, what the client POSTs, and the session-establishment steps.

Read-only.  python ntl_strings.py
"""
import re
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native1110\libUE4.so")

data = open(SO, "rb").read()
print("libUE4.so size = %.1f MB" % (len(data) / 1e6))

# --- find the NTL anchor and dump the surrounding printable-string window ---
anchor = b"ntl/api/GateInfo.php"
idx = data.find(anchor)
print("GateInfo.php anchor at offset %d (0x%x)" % (idx, idx))

# extract printable ASCII runs in a window around the anchor
def strings_in(buf, minlen=4):
    out = []
    cur = bytearray()
    start = 0
    for i, x in enumerate(buf):
        if 32 <= x < 127:
            if not cur:
                start = i
            cur.append(x)
        else:
            if len(cur) >= minlen:
                out.append((start, cur.decode()))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append((start, cur.decode()))
    return out


WIN = 60000
lo = max(0, idx - WIN)
hi = min(len(data), idx + WIN)
region = data[lo:hi]
print("\n=== NTL/PeerLink string window (offsets relative to anchor) ===")
seen = set()
for off, s in strings_in(region, 4):
    # keep only protocol-ish strings (endpoints, TURN/STUN/P2P/NTL/state names)
    if re.search(r"(?i)(\.php|/ntl/|turn|stun|hole|punch|relay|peer|nt l|ntl_|"
                 r"gateinfo|rendezvous|alloc|bind|session|sycom|host_direct|"
                 r"ice|candidate|dtls|session_control|qualitycheck|antenna)", s):
        if s in seen:
            continue
        seen.add(s)
        print("  %+7d  %s" % (off - (idx - lo), s[:160]))

# --- also: every distinct .php endpoint in the whole binary ---
print("\n=== every .php endpoint in libUE4.so ===")
php = sorted(set(re.findall(rb"[A-Za-z0-9_./]{4,80}\.php", data)))
for p in php:
    print("  " + p.decode())
