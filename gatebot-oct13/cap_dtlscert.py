"""Extract the DTLS handshake + certificate identity from the z2 capture.
The relay at 34.22.210.195:30970 answered the ClientHello with ~7
fragments of 228 B containing a konami-issued cert.  Concatenate the
return direction for that flow and pull the printable strings + the
certificate subject/issuer/ SAN, which names the relay service."""
import csv
import re
from collections import defaultdict

CAP = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
       r"\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv")

TARGET = "34.22.210.195"
T0 = 1790386204024          # first ClientHello ts for that flow
T1 = T0 + 4000              # the handshake burst


def l4(pkt: bytes):
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if pkt[9] == 6:
        off = (pkt[ihl + 12] >> 4) * 4
        return pkt[ihl + off:]
    if pkt[9] == 17:
        return pkt[ihl + 8:]
    return None


outb, inb = bytearray(), bytearray()
rows = []
with open(CAP, newline="", encoding="latin1") as f:
    for row in csv.DictReader(r for r in f if not r.startswith("#")):
        ts = int(row["ts_ms"])
        if not (T0 - 50 <= ts <= T1 + 50):
            continue
        if row["proto"] != "udp":
            continue
        if row["dir"] == "t" and row["dst"] != TARGET:
            continue
        p = l4(bytes.fromhex(row["payload_hex"]))
        if not p:
            continue
        rows.append((ts, row["dir"], len(p)))
        (outb if row["dir"] == "t" else inb).extend(p)

print("handshake-window packets:")
for ts, d, n in rows:
    print("  t+%6dms %s len=%d" % (ts - T0, d, n))

for name, blob in (("OUT (phone->relay)", outb), ("IN (relay->phone)", inb)):
    print("\n=== %s  %d bytes ===" % (name, len(blob)))
    strs = re.findall(rb"[\x20-\x7e]{5,}", bytes(blob))
    for s in strs:
        print("   ", s.decode("latin1"))

# the cert chain: look for DER SEQUENCE 30 82 and dump the CN/O/DC parts
print("\n=== DER-ish field strings (CN=, O=, OU=, DNS=) ===")
for m in re.finditer(rb"(?:CN|O|OU|DC|DNS|C)=([\x20-\x7e]{2,80})", bytes(inb)):
    print("   ", m.group(0).decode("latin1"))
