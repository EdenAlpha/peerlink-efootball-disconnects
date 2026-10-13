#!/usr/bin/env python3
"""tun_inner.py -- inner message type census + 080c session anatomy."""
import struct
import sys
from collections import Counter

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from pcapng_read import read_pcapng                                  # noqa: E402

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"


def main() -> int:
    pkts = read_pcapng(D + r"\m5\tunnel_capture.pcapng")
    frames = []
    for pkt in pkts:
        if len(pkt) < 42:
            continue
        ip = pkt[14:] if pkt[12:14] == b"\x08\x00" else pkt
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        b = ip[ihl + 8:]
        if len(b) < 12 or b[0] != 0 or b[1] != 0:
            continue
        if len(b) >= 20 and b[4:8] == b"\x21\x12\xa4\x42":
            continue
        src = ".".join(str(x) for x in ip[12:16])
        frames.append((src, b))
    print("frames: %d" % len(frames))

    # inner type = body[0:2]? test clustering on bodies 19-60B
    t2 = Counter()
    t4 = Counter()
    for _, b in frames:
        if 19 <= len(b) - 8 <= 60:
            t2[b[8:10].hex()] += 1
            t4[b[8:12].hex()] += 1
    print("\n=== body[0:2] census (top 20) ===")
    for k, c in t2.most_common(20):
        print("  %6d  %s" % (c, k))
    print("\n=== body[0:4] census (top 20) ===")
    for k, c in t4.most_common(20):
        print("  %6d  %s" % (k, c))

    # 080c anatomy across the session: counter progression + 0x0026 content
    print("\n=== 080c/090c exchanges (txid, counter, dir) first 12 ===")
    n = 0
    for _, _, _, _, _ in []:
        pass
    for pkt in pkts:
        if len(pkt) < 42:
            continue
        ip = pkt[14:] if pkt[12:14] == b"\x08\x00" else pkt
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        b = ip[ihl + 8:]
        if len(b) < 20 or b[4:8] != b"\x21\x12\xa4\x42":
            continue
        mt = struct.unpack("!H", b[:2])[0]
        if mt not in (0x080c, 0x090c):
            continue
        ml = struct.unpack("!H", b[2:4])[0]
        txid = b[8:20].hex()[:8]
        i = 20
        info = []
        while i + 4 <= 20 + ml and i + 4 <= len(b):
            at, al = struct.unpack("!HH", b[i:i + 4])
            v = b[i + 4:i + 4 + al]
            if at == 0x0026:
                nz = sum(1 for x in v if x)
                info.append("0026/%d:nonzero=%d head=%s" % (al, nz, v[:8].hex()))
            elif at in (0x9091, 0x909c):
                info.append("%04x: %s" % (at, v.hex()))
            i += 4 + al + (4 - al % 4) % 4
        src = ".".join(str(x) for x in ip[12:16])
        print("  %-15s 0x%04x len=%-4d tx=%s %s" % (src, mt, len(b), txid, info))
        n += 1
        if n >= 12:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
