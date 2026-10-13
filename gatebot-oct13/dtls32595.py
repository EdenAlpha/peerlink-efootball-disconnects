#!/usr/bin/env python3
"""dtls32595.py -- anatomy of the phone's direct DTLS channel (m1).

udp_trace (tunnel) has metadata only; the internet-side passthrough HAS full
bytes.  The phone holds a DTLS session to 35.230.139.74:32595 for the whole
match while the STUN punch goes through the tunnel.  Parse it: handshake
(SNI support), appdata cadence and sizes, first bytes vs kickoff.

  python dtls32595.py
"""
import struct
import sys
from collections import Counter

CAP = (r"C:\Users\Administrator\Documents\Default Project\work\plink"
       r"\m1\passthrough_capture.csv")


def records():
    out = []
    with open(CAP, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            p = line.split(",")
            if len(p) < 9 or p[2] != "udp":
                continue
            if p[6] != "32595" and p[4] != "32595":
                continue
            pkt = bytes.fromhex(p[8])
            ihl = (pkt[0] & 0xF) * 4
            out.append((int(p[0]), p[1], pkt[ihl + 8:]))
    return out


def main() -> int:
    recs = records()
    print("records: %d" % len(recs))
    t0 = min(t for t, _, _ in recs)
    print("t0=%d" % t0)

    rt_t, rt_r = Counter(), Counter()
    app_t, app_r = Counter(), Counter()
    first_app = {}
    hs = []
    for t, d, body in recs:
        if len(body) < 13:
            continue
        rt, ver, epoch = body[0], body[1:3], struct.unpack("!H", body[3:5])[0]
        rlen = struct.unpack("!H", body[11:13])[0]
        (rt_t if d == "t" else rt_r)[rt] += 1
        if rt == 22:
            hs.append((t, d, body))
        elif rt == 23:
            (app_t if d == "t" else app_r)[rlen] += 1
            if d not in first_app:
                first_app[d] = (t - t0) / 1000.0

    print("\nrecord types t:", dict(sorted(rt_t.items())))
    print("record types r:", dict(sorted(rt_r.items())))
    print("\nappdata record-len census t:", dict(sorted(app_t.items())))
    print("appdata record-len census r:", dict(sorted(app_r.items())))
    print("\nfirst appdata after t0: %s" % {
        k: "%.1fs" % v for k, v in first_app.items()})

    # parse the biggest client handshake as ClientHello (12B hs header)
    ch = None
    for t, d, body in hs:
        if d == "t" and len(body) > 100:
            ch = body[13:]
            break
    if ch and ch[0] == 1:
        ver = ch[12:14]
        rnd = ch[14:46]
        pos = 46
        sl = ch[pos]
        pos += 1 + sl
        cslen = struct.unpack("!H", ch[pos:pos + 2])[0]
        pos += 2
        print("\nClientHello ver=%s suites=%s" % (
            ver.hex(), ch[pos:pos + cslen].hex()))
        pos += cslen
        pos += 1 + ch[pos]
        extlen = struct.unpack("!H", ch[pos:pos + 2])[0]
        pos += 2
        end = pos + extlen
        print("extensions(%d):" % extlen)
        while pos + 4 <= end:
            et, el = struct.unpack("!HH", ch[pos:pos + 4])
            ed = ch[pos + 4:pos + 4 + el]
            extra = ""
            if et == 0 and len(ed) > 5:
                extra = "SNI=" + ed[5:].decode("latin-1", "replace")
            elif et == 13:
                extra = "sig_algs"
            elif et == 11:
                extra = "ec_point_formats"
            elif et == 10:
                extra = "elliptic_curves"
            elif et == 0x002b:
                extra = "supported_versions"
            print("  0x%04x len=%-4d %s" % (et, el, extra[:70]))
            pos += 4 + el
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
