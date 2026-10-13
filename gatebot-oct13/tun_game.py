#!/usr/bin/env python3
"""tun_game.py -- crack the 0x00 game frames + the 080a/080c signaling.

The tunnel underlay is plaintext: inner game bytes ride directly.  STUN
vendor methods 0x080a/0x090a/0x080b/0x090b/0x080c/0x090c parse like the
recovered punch template.  The 0x00 frames (22k in m5) are the game
exchange itself -- structure them: sizes, const vs varying offsets,
counters, direction symmetry.

  python tun_game.py [m4|m5]
"""
import struct
import sys
from collections import Counter

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"


def packets(m):
    sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
    from pcapng_read import read_pcapng
    out = []
    for pkt in read_pcapng(D + "\\%s\\tunnel_capture.pcapng" % m):
        if len(pkt) < 42:
            continue
        ip = pkt[14:] if pkt[12:14] == b"\x08\x00" else pkt
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        out.append((src, sport, dst, dport, ip[ihl + 8:]))
    return out


def main() -> int:
    m = sys.argv[1] if len(sys.argv) > 1 else "m5"
    pkts = packets(m)
    print("%s: %d inner packets" % (m, len(pkts)))

    # --- vendor STUN census with attr shapes ---
    print("\n=== vendor STUN (full attr decode) ===")
    shown = Counter()
    for src, sport, dst, dport, b in pkts:
        if len(b) >= 20 and b[4:8] == b"\x21\x12\xa4\x42":
            mt = struct.unpack("!H", b[:2])[0]
            if shown[(mt, len(b))] < 2:
                shown[(mt, len(b))] += 1
                i, attrs = 20, []
                ml = struct.unpack("!H", b[2:4])[0]
                while i + 4 <= 20 + ml and i + 4 <= len(b):
                    at, al = struct.unpack("!HH", b[i:i + 4])
                    v = b[i + 4:i + 4 + al]
                    try:
                        txt = v.rstrip(b"\x00").decode("ascii")
                        if not txt.isprintable():
                            txt = ""
                    except UnicodeDecodeError:
                        txt = ""
                    attrs.append("0x%04x/%d:%s%s" % (
                        at, al, v[:16].hex(), (" ascii=%r" % txt) if txt else ""))
                    i += 4 + al + (4 - al % 4) % 4
                print("  %s:%s -> %s:%s type=0x%04x len=%d txid=%s" % (
                    src, sport, dst, dport, mt, len(b), b[8:12].hex()))
                for a in attrs:
                    print("      %s" % a)
    # count per type
    tc = Counter()
    for _, _, _, _, b in pkts:
        if len(b) >= 20 and b[4:8] == b"\x21\x12\xa4\x42":
            tc["0x%04x" % struct.unpack("!H", b[:2])[0]] += 1
    print("  census:", dict(sorted(tc.items())))

    # --- 0x00 game frames ---
    g = [b for _, _, _, _, b in pkts
         if len(b) >= 4 and not (
             len(b) >= 20 and b[4:8] == b"\x21\x12\xa4\x42")]
    print("\n=== 0x00 game frames: %d ===" % len(g))
    print("  len census:", dict(sorted(Counter(len(b) for b in g).items())))
    if not g:
        return 0
    maxl = max(len(b) for b in g)
    print("  max len %d; column analysis over first %d (min len %d):" % (
        maxl, min(32, min(len(b) for b in g)), min(len(b) for b in g)))
    n0 = min(32, min(len(b) for b in g))
    for i in range(n0):
        vals = Counter(b[i] for b in g)
        if len(vals) == 1:
            print("    [%2d] const 0x%02x" % (i, next(iter(vals))))
        elif len(vals) <= 8:
            print("    [%2d] %d vals %s" % (
                i, len(vals),
                sorted(vals.items())[:8]))
        else:
            print("    [%2d] %d distinct vals (counter/hash-like)" % (i, len(vals)))
    # direction symmetry on game frames
    dc = Counter()
    for src, sport, dst, dport, b in pkts:
        if b in g or (len(b) >= 4 and b in g):
            pass
    gg = [(s, p, d, q) for s, p, d, q, b in pkts if any(b is x for x in g)]
    for s, p, d, q in gg:
        dc[(s, d)] += 1
    print("  direction:", dict(dc))
    # first 3 game frames hex
    print("  first frames:")
    for b in g[:3]:
        print("    %dB %s" % (len(b), b[:48].hex()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
