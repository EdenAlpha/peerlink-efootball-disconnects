"""Test the published eFootball decryption key against real captured traffic.

Key + pipeline from github.com/nyandev-55/efbmobiledecrypt (2026-09-02):
  payload = IV[16] + AES-256-CBC(key, ciphertext)
  plain   = gzip(payload_decrypted)
  msgpack.unpackb(plain)

We have real match captures (captures/match-2026-09-26). Try the pipeline
against every plausible payload chunk found in them. A single successful
msgpack decode is proof; zero successes means the key/pipeline does not match
this traffic (which itself is a finding: maybe P2P UDP is a different layer).
"""
import gzip
import re
import sys
import zlib

import msgpack
from Crypto.Cipher import AES

KEY = bytes.fromhex("43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")


def try_decode(blob: bytes):
    """Return msgpack object if this blob decrypts, else None."""
    if len(blob) < 32 or len(blob) % 16 != 0:
        return None
    iv, ct = blob[:16], blob[16:]
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    # gzip (with header) or raw deflate
    for fn in (
        lambda b: gzip.decompress(b),
        lambda b: zlib.decompress(b, 16 + zlib.MAX_WBITS),
        lambda b: zlib.decompress(b),
        lambda b: zlib.decompress(b, -15),
    ):
        try:
            out = fn(pt)
        except Exception:
            continue
        try:
            obj = msgpack.unpackb(out, raw=False, strict_map_key=False)
            return obj
        except Exception:
            continue
    # maybe already msgpack without compression
    try:
        return msgpack.unpackb(pt, raw=False, strict_map_key=False)
    except Exception:
        return None


def main(path: str) -> int:
    data = open(path, "rb").read()
    print(f"file {path}: {len(data)} bytes")
    # Look for hex columns (CSV) and raw base64/hex blobs
    hexes = re.findall(rb"\b[0-9a-fA-F]{64,}\b", data)
    print(f"  hex-looking tokens: {len(hexes)}")
    # Also scan raw bytes aligned to 16, sampled: too big to brute force all
    hits = 0
    seen = 0
    for tok in hexes[:4000]:
        tok = tok[: len(tok) - (len(tok) % 16)]
        if len(tok) < 32:
            continue
        seen += 1
        obj = try_decode(bytes.fromhex(tok.decode()))
        if obj is not None:
            hits += 1
            print("  DECODED:", str(obj)[:400])
            if hits >= 3:
                break
    # raw byte-window scan on the file body
    raw_hits = 0
    step = 32
    for off in range(0, min(len(data), 400000), step):
        chunk = data[off: off + 64]
        if len(chunk) < 64:
            break
        obj = try_decode(chunk)
        if obj is not None:
            raw_hits += 1
            print(f"  RAW DECODED @ {off}:", str(obj)[:300])
            if raw_hits >= 3:
                break
    print(f"  tried {seen} hex tokens + raw windows; hits={hits + raw_hits}")
    return 0 if (hits + raw_hits) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
