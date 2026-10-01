#!/usr/bin/env python3
"""Find gzipped request bodies in a memory dump and decompress them.

Why
---
The game's own memory shows how it builds each gate request:

    SetContentType(): application/x-www-form-urlencoded
      useGzip = true
      cookie  = sign=<44 base64 chars>
    setRequestProperty pes-custom-encrypt:AES256

So the body is form-urlencoded, then GZIPPED, then AES-256 encrypted. That
ordering is the opening: the gzip step happens before the AES step, so a
complete, uncompressed-as-it-were plaintext body exists in the heap as a live
gzip stream. Every `1f 8b` in a writable region is a candidate, and each one
that inflates cleanly to form-encoded text is a captured request body -- no key
required.

This is deliberately not a heuristic search for "interesting-looking bytes".
It looks for the one two-byte magic that the app's own log says will be there,
and then requires the payload to actually inflate.

Usage:
    python3 find_gzip_in_mem.py <region.bin> [region.bin ...]
    python3 find_gzip_in_mem.py /tmp/kgs/memdump/*.bin --min-out 16
"""
from __future__ import annotations

import argparse
import glob
import gzip
import io
import re
import sys

MAGIC = b"\x1f\x8b"


def looks_like_body(text: str) -> bool:
    """True when the inflated text looks like the thing we are hunting."""
    if "=" not in text:
        return False
    return bool(
        re.search(r"(uid|opt|libVer|token|cmd|ver|device|lang)", text, re.I)
    )


def try_inflate(blob: bytes, offset: int):
    """Try to inflate a gzip member at `offset`, tolerating trailing junk."""
    for end in (len(blob), min(len(blob), offset + 262144)):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(blob[offset:end])) as fh:
                data = fh.read()
        except Exception:
            continue
        if data:
            return data
    # Raw deflate fallback: some builds emit a bare deflate stream.
    import zlib

    for wbits in (-15, 15, 47):
        try:
            d = zlib.decompressobj(wbits)
            data = d.decompress(blob[offset : offset + 262144])
            if data:
                return data
        except Exception:
            continue
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--min-out", type=int, default=16)
    ap.add_argument("--max-hits", type=int, default=40)
    ap.add_argument("--show", type=int, default=600)
    args = ap.parse_args()

    paths = []
    for f in args.files:
        paths.extend(sorted(glob.glob(f)) or [f])

    total_candidates = 0
    hits = 0

    for path in paths:
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            print("skip %s: %s" % (path, exc))
            continue

        start = 0
        found_here = 0
        while True:
            idx = blob.find(MAGIC, start)
            if idx < 0:
                break
            start = idx + 1
            total_candidates += 1
            data = try_inflate(blob, idx)
            if not data or len(data) < args.min_out:
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("latin-1", "replace")
            if not looks_like_body(text):
                continue

            hits += 1
            found_here += 1
            print("=" * 74)
            print("HIT %s at 0x%x  inflated %d bytes" % (path, idx, len(data)))
            print(text[: args.show])
            if hits >= args.max_hits:
                break
        if found_here:
            print("-" * 74)
            print("%s: %d bodies" % (path, found_here))

    print("=" * 74)
    print("scanned %d file(s), %d gzip candidates, %d request bodies"
          % (len(paths), total_candidates, hits))
    return 0 if hits else 2


if __name__ == "__main__":
    raise SystemExit(main())
