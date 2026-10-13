"""Extract SNI from every TLS ClientHello in the z2 capture.
payload_hex is a COMPLETE IP packet -> strip IPv4 + TCP/UDP headers first.
Answers: which hostname did the phone fetch the DTLS/session-server
address from, ~1.8 s before it opened the DTLS sessions to GCP?"""
import csv
import struct

CAP = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
       r"\captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv")


def l4_payload(pkt: bytes):
    """Strip IPv4 header (+ TCP/UDP) -> transport payload."""
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    proto = pkt[9]
    if proto == 6:                                   # TCP
        if len(pkt) < ihl + 20:
            return None
        off = (pkt[ihl + 12] >> 4) * 4
        return pkt[ihl + off:]
    if proto == 17:                                  # UDP
        return pkt[ihl + 8:]
    return None


def sni_of(p: bytes):
    """SNI hostname from a TLS ClientHello record.  None for DTLS/other."""
    if not p or len(p) < 43 or p[0] != 0x16:
        return None
    if p[1] == 0xFE:                                 # DTLS record version
        return None
    if p[5] != 0x01:                                 # handshake type != hello
        return None
    i = 5 + 4 + 2 + 32                               # hs hdr + ver + random
    try:
        i += 1 + p[i]
        i += 2 + struct.unpack(">H", p[i:i + 2])[0]
        i += 1 + p[i]
        if i + 2 > len(p):
            return None
        end = i + 2 + struct.unpack(">H", p[i:i + 2])[0]
        i += 2
        while i + 4 <= end and i + 4 <= len(p):
            et, el = struct.unpack(">HH", p[i:i + 4])
            if et == 0x0000:                         # server_name
                j = i + 4 + 5
                nlen = struct.unpack(">H", p[i + 4 + 5:i + 4 + 7])[0]
                return p[j:j + nlen].decode("latin1")
            i += 4 + el
    except Exception:                                # noqa: BLE001
        return None
    return None


found, dtls = {}, []
with open(CAP, newline="", encoding="latin1") as f:
    rows = (r for r in f if not r.startswith("#"))
    for row in csv.DictReader(rows):
        raw = row.get("payload_hex") or ""
        if len(raw) < 40:
            continue
        try:
            pkt = bytes.fromhex(raw)
        except ValueError:
            continue
        p = l4_payload(pkt)
        if not p:
            continue
        if len(p) > 13 and p[0] == 0x16 and p[1] == 0xFE:
            dtls.append((row["ts_ms"], row["dir"], row["dst"], row["dport"],
                         len(p)))
        h = sni_of(p)
        if h:
            k = (row["dir"], row["dst"], row["dport"], h)
            found[k] = found.get(k, 0) + 1

print("=== SNI (TLS ClientHello) ===")
if found:
    for (d, dst, dport, h), n in sorted(found.items()):
        print("  %s -> %s:%s  SNI=%-45s n=%d" % (d, dst, dport, h, n))
else:
    print("  none found")

print("\n=== DTLS records (16 fe ..) ===")
for ts, d, dst, dp, n in dtls[:20]:
    print("  ts=%s %s -> %s:%s len=%d" % (ts, d, dst, dp, n))
print("  total DTLS packets:", len(dtls))
