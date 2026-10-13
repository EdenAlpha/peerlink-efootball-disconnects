#!/usr/bin/env python3
"""punch_corpus.py -- every direct-path game packet across all 3 captures.

udp_trace (tunnel) is metadata-only (verified: 32 cols, zero payload --
column census {32:30100}).  The passthrough files carry full bytes of
internet-side traffic.  Pull every UDP packet on the game ports (1162,
42010, and the 17024/17025 match-control channel) from all three
passthrough captures and STUN-parse each one byte-exact.
"""
import struct

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"
GAME_PORTS = {"1162", "42010", "17024", "17025"}


def parse_stun(body):
    if len(body) < 4:
        return "empty<%d>" % len(body)
    if len(body) < 20:
        return "short<%d> %s" % (len(body), body.hex())
    mt, ml = struct.unpack("!HH", body[:4])
    if body[4:8] != b"\x21\x12\xa4\x42":
        return "NOMAGIC type=0x%04x" % mt
    txid = body[8:20].hex()
    attrs = []
    i = 20
    ok = True
    while i + 4 <= 20 + ml and i + 4 <= len(body):
        at, al = struct.unpack("!HH", body[i:i + 4])
        v = body[i + 4:i + 4 + al]
        attrs.append((at, al, v))
        i += 4 + al + (4 - al % 4) % 4
    if 20 + ml != i:
        ok = False
    cls = "req" if (mt & 0x0110) == 0 else (
        "resp" if (mt & 0x0110) == 0x0100 else "ind/err")
    return (mt, ml, txid, attrs, ok, cls)


def main() -> int:
    total = 0
    for m in ("m1", "m2", "m3"):
        print("=== %s ===" % m)
        try:
            f = open(D + "\\%s\\passthrough_capture.csv" % m,
                     encoding="utf-8", errors="replace")
        except OSError as e:
            print("  cannot open: %s" % e)
            continue
        for line in f:
            if line.startswith("#"):
                continue
            p = line.split(",")
            if len(p) < 9 or p[2] != "udp":
                continue
            if p[4] not in GAME_PORTS and p[6] not in GAME_PORTS:
                continue
            pkt = bytes.fromhex(p[8])
            ihl = (pkt[0] & 0xF) * 4
            body = pkt[ihl + 8:]
            r = parse_stun(body)
            total += 1
            print("  %s %s:%s -> %s:%s  udpbody=%d"
                  % (p[1], p[3], p[4], p[5], p[6], len(body)))
            if isinstance(r, str):
                print("    %s" % r)
                continue
            mt, ml, txid, attrs, ok, cls = r
            print("    STUN type=0x%04x(%s) len=%d txid=%s framing_ok=%s"
                  % (mt, cls, ml, txid[:16] + "..", ok))
            for at, al, v in attrs:
                try:
                    txt = v.rstrip(b"\x00").decode("ascii")
                    show = "ascii=%r" % txt if txt.isprintable() else ""
                except UnicodeDecodeError:
                    show = ""
                print("      attr 0x%04x len=%-3d %s %s"
                      % (at, al, v[:28].hex(), show))
    print("\ntotal direct game packets: %d" % total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
