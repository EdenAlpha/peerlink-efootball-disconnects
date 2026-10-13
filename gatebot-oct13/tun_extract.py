#!/usr/bin/env python3
"""tun_extract.py -- dump EVERY inner packet's bytes from both pcapng files.

Output per match: <m>_inner.jsonl, one row per packet:
  {i, dir, src, sport, dst, dport, len, seq, cls, hex}
dir = out (10.58.176.146, this phone) | in (peer).  seq/cls = outer 0x00
header fields when present, else null (STUN vendor frames have no outer
header -- their type is in stun_type).

  python tun_extract.py
"""
import json
import struct
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from pcapng_read import read_pcapng                                  # noqa: E402

D = r"C:\Users\Administrator\Documents\Default Project\work\plink"
ME = "10.58.176.146"


def main() -> int:
    for m in ("m4", "m5"):
        pkts = read_pcapng(D + "\\%s\\tunnel_capture.pcapng" % m)
        n_out = n_in = n_stun = n_game = n_other = 0
        with open(D + "\\%s_inner.jsonl" % m, "w",
                  encoding="utf-8") as f:
            for i, pkt in enumerate(pkts):
                if len(pkt) < 20:
                    continue
                ip = pkt[14:] if len(pkt) >= 14 and pkt[12:14] == b"\x08\x00" \
                    else pkt
                if (ip[0] >> 4) != 4:
                    continue
                ihl = (ip[0] & 0xF) * 4
                if ip[9] != 17 or len(ip) < ihl + 8:
                    continue
                sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
                src = ".".join(str(b) for b in ip[12:16])
                dst = ".".join(str(b) for b in ip[16:20])
                b = ip[ihl + 8:]
                d = "out" if src == ME else "in"
                if d == "out":
                    n_out += 1
                else:
                    n_in += 1
                row = {"i": i, "dir": d, "src": src, "sport": sport,
                       "dst": dst, "dport": dport, "len": len(b),
                       "hex": b.hex()}
                if len(b) >= 20 and b[4:8] == b"\x21\x12\xa4\x42":
                    mt = struct.unpack("!H", b[:2])[0]
                    row["stun_type"] = "0x%04x" % mt
                    row["txid"] = b[8:20].hex()
                    n_stun += 1
                elif len(b) >= 8 and b[0] == 0 and b[1] == 0:
                    row["seq"] = (b[2] << 8) | b[3]
                    row["cls"] = "0x%02x" % b[4]
                    n_game += 1
                else:
                    n_other += 1
                f.write(json.dumps(row) + "\n")
        print("%s: out=%d in=%d stun=%d game=%d other=%d" % (
            m, n_out, n_in, n_stun, n_game, n_other))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
