#!/usr/bin/env python3
"""plink_seq.py -- pre-kickoff big-packet flight structure + DTLS SNI fix."""
import struct

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"
T0 = 182400.0
CAP = D + r"\m1\passthrough_capture.csv"


def main() -> int:
    print("=== big-packet flight sequence, m1 t=0..60s (rel_s dir len) ===")
    rows = []
    for line in open(D + r"\m1\udp_trace.csv", encoding="utf-8",
                     errors="replace"):
        if line.startswith("#"):
            continue
        p = line.split(",")
        if len(p) < 31:
            continue
        try:
            rel = float(p[9])
        except ValueError:
            continue
        if rel < 60000 and int(p[6]) >= 300:
            rows.append((rel / 1000.0, p[2], int(p[6])))
    for rel, d, L in rows:
        print("  t=%6.1fs %-3s len=%4d" % (rel, d, L))

    # mirror check on m3: same multiset of (dir,len) pre-T0?
    from collections import Counter
    for m in ("m1", "m3"):
        c = Counter()
        for line in open(D + r"\%s\udp_trace.csv" % m, encoding="utf-8",
                         errors="replace"):
            if line.startswith("#"):
                continue
            p = line.split(",")
            if len(p) < 31:
                continue
            try:
                rel = float(p[9])
            except ValueError:
                continue
            if rel < T0 and int(p[6]) >= 300:
                c[(p[2], int(p[6]))] += 1
        print("\n%s big-packet (dir,len) multiset: %d distinct" % (m, len(c)))
        # compare as mirror: m1 out==m3 in and vice versa
    print("\n=== SNI from 32595 ClientHello (cookie-aware parse) ===")
    for line in open(CAP, encoding="utf-8", errors="replace"):
        if line.startswith("#"):
            continue
        p = line.split(",")
        if len(p) < 9 or p[2] != "udp" or p[1] != "t":
            continue
        if p[6] != "32595" and p[4] != "32595":
            continue
        pkt = bytes.fromhex(p[8])
        ihl = (pkt[0] & 0xF) * 4
        body = pkt[ihl + 8:]
        if len(body) < 30 or body[0] != 22:
            continue
        ch = body[13:]
        if ch[0] != 1 or len(ch) < 50:
            continue
        pos = 12 + 2 + 32          # ver + random
        sl = ch[pos]
        pos += 1 + sl              # session_id
        cl = ch[pos]
        pos += 1 + cl              # cookie (hello_verify echo)
        if pos + 2 > len(ch):
            continue
        cslen = struct.unpack("!H", ch[pos:pos + 2])[0]
        pos += 2
        suites = ch[pos:pos + cslen].hex()
        pos += cslen
        if pos >= len(ch):
            continue
        pos += 1 + ch[pos]         # compression
        if pos + 2 > len(ch):
            continue
        extlen = struct.unpack("!H", ch[pos:pos + 2])[0]
        pos += 2
        end = pos + extlen
        print("suites:", suites)
        while pos + 4 <= end and pos + 4 <= len(ch):
            et, el = struct.unpack("!HH", ch[pos:pos + 4])
            ed = ch[pos + 4:pos + 4 + el]
            extra = ""
            if et == 0 and len(ed) > 5:
                extra = "SNI=" + ed[5:].decode("latin-1", "replace")
            print("  ext 0x%04x len=%-4d %s" % (et, el, extra[:70]))
            pos += 4 + el
        break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
