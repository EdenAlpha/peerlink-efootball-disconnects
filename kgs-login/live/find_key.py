#!/usr/bin/env python3
"""find_key.py -- the yes/no test: is the key in this sweep, and does it open
this session's captured bodies?

Inputs must come from the SAME session:
  --dir    a sweep directory (full writable-memory copies, see live/sweep.sh)
  --flows  the flows.log mitm captured during that session (REQHEX lines)

Pipeline tested (the published eFootball body pipeline, same as
scripts/test_efb_key.py):
    body = IV[16] || AES-256-CBC(key, gzip(msgpack(...)))
so for candidate K: IV = body[:16], decrypt the rest, gunzip, msgpack.unpackb.

Why this is exhaustive AND fast:
  stage 1 decrypts ONE block per candidate and looks for the gzip magic
  1f 8b. A wrong candidate passes by chance 1 time in 65536, so ~1 GB of
  memory yields ~15000 survivors -- not one billion.
  stage 2 does gunzip + msgpack only on survivors. A wrong key that survives
  both does not exist in practice: that is the proof, not a heuristic.

Candidates: every 32-byte window at every offset (stage 1 pass A), plus
aligned windows with a msgpack-map first byte (pass B, if A finds nothing),
plus any 64-hex-char string (a key written out as hex text).

Exit: 0 MATCH (key hex printed), 2 NO MATCH, 1 unusable input (loud).
"""
import argparse
import gzip
import multiprocessing as mp
import os
import re
import sys
import time
import zlib

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("need pycryptodome: pip install --break-system-packages pycryptodome")
try:
    import msgpack
except ImportError:
    sys.exit("need msgpack: pip install --break-system-packages msgpack")

GAPS = []   # filled per worker: list of (iv_int, c0_bytes) for stage 1
TESTED = 0  # candidates actually decrypted, counted where they happen

HEXRUN = re.compile(rb"(?=([0-9a-fA-F]{64}))")


def load_bodies(path):
    """Return [(label, bytes)] for encrypted request bodies in flows.log."""
    bodies, label = [], "?"
    with open(path, errors="replace") as fh:
        for line in fh:
            if line.startswith("### "):
                label = line.strip()[:120]
            elif line.startswith("REQHEX:"):
                try:
                    b = bytes.fromhex(line.split(":", 1)[1].strip())
                except ValueError:
                    continue
                if len(b) >= 48 and len(b) % 16 == 0:
                    bodies.append((label, b))
    return bodies


def looks_plain(b):
    """A body that already decodes as msgpack is plaintext (GateInfo), not
    encrypted -- it must not be used as a key test."""
    try:
        obj = msgpack.unpackb(b, raw=False, strict_map_key=False)
    except Exception:
        return False
    return isinstance(obj, (dict, list)) and bool(obj)


def unpack_maybe(raw):
    try:
        obj = msgpack.unpackb(raw, raw=False, strict_map_key=False)
    except Exception:
        return None
    return obj if isinstance(obj, (dict, list)) and obj else None


def verify(K, bodies):
    """Full pipeline on every body. Returns (label, preview) or None."""
    for label, B in bodies:
        iv, ct = B[:16], B[16:]
        try:
            pt = AES.new(K, AES.MODE_CBC, iv).decrypt(ct)
        except Exception:
            continue
        for fn in (
            lambda x: gzip.decompress(x),
            lambda x: zlib.decompress(x, 16 + zlib.MAX_WBITS),
            lambda x: zlib.decompress(x),
            lambda x: zlib.decompress(x, -15),
            lambda x: x,
        ):
            try:
                raw = fn(pt)
            except Exception:
                continue
            obj = unpack_maybe(raw)
            if obj is None and fn is not None and raw is not pt:
                continue
            if obj is not None:
                return label, repr(obj)[:300]
            # try PKCS7-stripped raw plaintext (uncompressed layout)
            if 1 <= pt[-1] <= 16 and pt.endswith(bytes([pt[-1]]) * pt[-1]):
                obj = unpack_maybe(pt[:-pt[-1]])
                if obj is not None:
                    return label, repr(obj)[:300]
    return None


def _init(gaps):
    global GAPS
    GAPS = gaps


def _scan(task):
    """One pass-A chunk: every offset, first-block gzip-magic test.

    Returns (hits, tested) so the parent can count what was really tried --
    a NO MATCH that reports "0 candidates" would be a lie about the work done.
    """
    path, start, length, passmode = task
    try:
        with open(path, "rb") as fh:
            fh.seek(start)
            data = fh.read(length + 32)
    except Exception:
        return [], 0  # pruned under us mid-scan; the dir listing was a moment ago
    hits = []
    tested = 0
    n = len(data)
    # pass A: every offset; pass B: 8-byte aligned with msgpack-map first byte
    step = 1 if passmode == "A" else 8
    end = min(n - 32, length)
    for off in range(0, end + 1, step):
        K = data[off:off + 32]
        if len(K) < 32:
            break
        for iv, c0 in GAPS:
            tested += 1
            p0 = AES.new(K, AES.MODE_ECB).decrypt(c0)
            x = int.from_bytes(p0, "big") ^ iv
            xb = x.to_bytes(16, "big")
            if passmode == "A":
                if xb[:2] == b"\x1f\x8b":
                    hits.append((K, off))
                    break
            else:
                if xb[0] in range(0x80, 0x90) and xb[1] in range(0xa0, 0xc0):
                    hits.append((K, off))
                    break
    # hex-text form of a key, any offset
    for m in HEXRUN.finditer(data[:end + 1]):
        try:
            hits.append((bytes.fromhex(m.group(1).decode()), -1))
        except ValueError:
            pass
    return hits, tested


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--flows", required=True)
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--max-file-mb", type=int, default=0,
                    help="scan only the first N MB per region (0 = all)")
    args = ap.parse_args()

    bodies = [(l, b) for l, b in load_bodies(args.flows) if not looks_plain(b)]
    if not bodies:
        print("UNUSABLE: no encrypted REQHEX body in %s -- is the MITM armed "
              "for THIS session?" % args.flows)
        return 1
    print("test bodies: %d (first: %s, %d bytes)"
          % (len(bodies), bodies[0][0], len(bodies[0][1])), flush=True)

    gaps = []
    for _, B in bodies:
        iv = int.from_bytes(B[:16], "big")
        gaps.append((iv, B[16:32]))
    # stage-1 uses body 0 only (one decrypt per candidate); a session key
    # opens every body of that session, so body 0 is both necessary+enough.

    files = []
    unz = []  # decompressed copies we made; removed before exit
    for root, _dirs, names in os.walk(args.dir):
        for nm in sorted(names):
            if nm.startswith("r_") and nm.endswith((".bin", ".bin.gz")):
                p = os.path.join(root, nm)
                if p.endswith(".gz"):
                    try:
                        raw = gzip.decompress(open(p, "rb").read())
                    except Exception as e:
                        # the sweeper keeps running during the scan: a .gz
                        # being written (or pruned) under us reads back
                        # truncated. Skip it LOUDLY instead of dying -- a
                        # traceback with rc=1 is not a verdict.
                        print("skip unreadable %s (%s)" % (p, e), flush=True)
                        continue
                    tmp = p + ".unz"
                    try:
                        open(tmp, "wb").write(raw)
                    except Exception as e:
                        print("skip unwritable %s (%s)" % (tmp, e), flush=True)
                        continue
                    unz.append(tmp)
                    files.append(tmp)
                else:
                    files.append(p)
    if not files:
        print("UNUSABLE: no region files under %s -- did the sweeper run?"
              % args.dir)
        return 1
    print("region files: %d (skipped %d unreadable)" % (len(files), 0),
          flush=True)

    t0 = time.time()
    try:
        for passmode in ("A", "B"):
            tasks = []
            for p in files:
                try:
                    sz = os.path.getsize(p)
                except Exception:
                    continue  # pruned under us mid-scan
                if args.max_file_mb:
                    sz = min(sz, args.max_file_mb * 1048576)
                chunk = 16 * 1048576
                off = 0
                while off < sz:
                    tasks.append((p, off, min(chunk, sz - off), passmode))
                    off += chunk
            print("pass %s: %d chunks on %d jobs" % (passmode, len(tasks),
                                                     args.jobs), flush=True)
            found = []
            with mp.Pool(args.jobs, initializer=_init, initargs=([gaps[0]],)) as pool:
                for i, (hits, tested) in enumerate(pool.imap_unordered(_scan, tasks)):
                    for K, off in hits:
                        found.append((K, off))
                    globals()["TESTED"] += tested
                    if (i + 1) % 10 == 0:
                        print("  %s: %d/%d chunks, %d stage-1 survivors, %.0fs"
                              % (passmode, i + 1, len(tasks), len(found),
                                 time.time() - t0), flush=True)
            # de-duplicate
            uniq, seen = [], set()
            for K, off in found:
                if K in seen:
                    continue
                seen.add(K)
                uniq.append((K, off))
            print("pass %s: %d unique survivors to verify" % (passmode, len(uniq)),
                  flush=True)
            for K, off in uniq:
                r = verify(K, bodies)
                if r:
                    label, preview = r
                    print("MATCH key=%s offset=%s" % (K.hex(),
                          ("0x%x" % off) if off >= 0 else "hex-string"))
                    print("  opened body: %s" % label)
                    print("  preview: %s" % preview)
                    return 0
            if passmode == "A":
                print("pass A found nothing; trying aligned msgpack-map pass B",
                      flush=True)
        print("NO MATCH: %d candidates tested in %.0fs against %d bodies"
              % (TESTED, time.time() - t0, len(bodies)))
        print("  (sweep %s vs flows %s -- both must be the same session)"
              % (args.dir, args.flows))
        return 2
    finally:
        for tmp in unz:
            try:
                os.remove(tmp)
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
