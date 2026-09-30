"""Test the published eFootball key against REAL match captures, properly.

The passthrough captures are full IP packets in hex. My first attempt
decrypted the whole packet (IP headers included) - that always fails. This
strips IP + UDP/TCP headers first, then tries the published pipeline on the
actual application payload:

  payload = IV[16] + AES-256-CBC(key, ct)
  plain   = gzip -> msgpack

A single msgpack decode = the key works. Zero = key/pipeline wrong OR this
traffic is a different layer (P2P match UDP vs command gRPC).
"""
import csv
import gzip
import sys
import zlib

import msgpack
from Crypto.Cipher import AES

KEY = bytes.fromhex("43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")


def try_decode(blob: bytes):
    if len(blob) < 32 or len(blob) % 16 != 0:
        return None
    iv, ct = blob[:16], blob[16:]
    try:
        pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    except Exception:
        return None
    cands = [pt]
    for fn in (
        lambda b: gzip.decompress(b),
        lambda b: zlib.decompress(b, 16 + zlib.MAX_WBITS),
        lambda b: zlib.decompress(b),
        lambda b: zlib.decompress(b, -15),
    ):
        try:
            cands.append(fn(pt))
        except Exception:
            pass
    for c in cands:
        try:
            return msgpack.unpackb(c, raw=False, strict_map_key=False)
        except Exception:
            pass
    return None


def is_meaningful(obj):
    """Filter out coincidental decodes: a real packet decodes to a dict/list
    with string keys/values, not just a bare number."""
    if isinstance(obj, dict):
        return len(obj) > 0 and all(isinstance(k, (str, bytes)) for k in obj)
    if isinstance(obj, (list, tuple)):
        return len(obj) > 0 and any(isinstance(x, (dict, str)) for x in obj)
    return False


def udp_payload(pkt: bytes):
    """Strip IPv4 header + UDP header, return application payload."""
    if len(pkt) < 28:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if pkt[9] != 17:  # not UDP
        return None
    if ihl + 8 > len(pkt):
        return None
    return pkt[ihl + 8:]


def tcp_payload(pkt: bytes):
    if len(pkt) < 40:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if pkt[9] != 6:
        return None
    if ihl + 20 > len(pkt):
        return None
    doff = ((pkt[ihl + 12] >> 4) & 0x0F) * 4
    return pkt[ihl + doff:]


def main(path: str) -> int:
    udp_n = tcp_n = 0
    hits = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        rd = csv.reader(f)
        for row in rd:
            if not row or row[0].startswith("#") or row[0] == "ts_ms":
                continue
            if len(row) < 9:
                continue
            proto, hexs = row[2], row[8]
            try:
                pkt = bytes.fromhex(hexs)
            except Exception:
                continue
            for kind, fn in (("udp", udp_payload), ("tcp", tcp_payload)):
                pl = fn(pkt)
                if not pl:
                    continue
                if kind == "udp":
                    udp_n += 1
                else:
                    tcp_n += 1
                # try payload as-is and a few alignments
                for off in range(0, min(32, len(pl))):
                    obj = try_decode(pl[off:])
                    if obj is not None and is_meaningful(obj):
                        hits += 1
                        print(f"  DECODED ({kind} @off {off}):", str(obj)[:400])
                        if hits >= 5:
                            print(f"\nudp={udp_n} tcp={tcp_n} hits={hits}")
                            return 0
    print(f"\nudp payloads tried={udp_n} tcp={tcp_n}  hits={hits}")
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
