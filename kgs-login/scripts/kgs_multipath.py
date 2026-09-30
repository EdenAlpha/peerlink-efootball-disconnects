#!/usr/bin/env python3
"""Probe many candidate command routes in one run, cheaply.

The route table is the single remaining unknown, and the endpoint answers an
unknown route deterministically: `14` (UNAVAILABLE, surfacing as HTTP 502) every
time, versus a real `CommandResponse` for a route that resolves. So a candidate
can be classified by asking, and the only cost is time.

That time is the constraint. Each candidate needs its own TLS connection, so
probing them one at a time serially is far too slow to cover a large candidate
set. This drives many connections concurrently, and it re-probes every
candidate that comes back `14` so a transient cannot be mistaken for a verdict.

Two things this deliberately does not do:

  * it does not send anything resembling a credential. A route that resolves is
    identified by the *absence* of 14, and the caller supplies the real payload
    afterwards via kgs_call.py once the route is known.
  * it does not treat a single sample as conclusive. The endpoint has a ~0.7%
    transient (measured 18/2711), so any candidate is confirmed with
    `--repeat` samples before being believed.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402


def probe(path, payload, pack):
    """Return (outcome, detail). Outcome is 'route', 'unknown' or 'error'."""
    try:
        r = call(path, payload, pack, str(uuid.uuid4()), settle=3.0)
    except Exception as e:
        return "error", "%s: %s" % (type(e).__name__, e)
    grpc = None
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            grpc = h["grpc-status"]
    d = r["data"]
    cmd = None
    res = None
    if len(d) >= 5:
        mlen = int.from_bytes(d[1:5], "big")
        dec = command_response(d[5:5 + mlen])
        cmd = dec.get("id")
        res = dec.get("res")
    if grpc == "14" or (grpc is None and cmd is None):
        return "unknown", "grpc=%s cmd=%s" % (grpc, cmd)
    return "route", "grpc=%s cmd=%s res=%s" % (
        grpc, cmd, (res or "")[:120])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="candidate paths to probe")
    ap.add_argument("--file", help="file of candidate paths, one per line")
    ap.add_argument("--req", default="{}")
    ap.add_argument("--pack", type=int, default=0, choices=(0, 1))
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--repeat", type=int, default=3,
                    help="re-probe each candidate this many times")
    a = ap.parse_args()

    cands = list(a.paths)
    if a.file:
        with open(a.file, encoding="utf-8", errors="replace") as f:
            cands += [ln.strip() for ln in f if ln.strip()]
    cands = list(dict.fromkeys(cands))
    if not cands:
        print("no candidates given")
        return 2

    print("probing %d candidate route(s), %d sample(s) each, %d workers"
          % (len(cands), a.repeat, a.workers))
    print("  an unknown route answers 14 (HTTP 502) every time;")
    print("  a real route answers with a CommandResponse.\n")

    hits = []
    tally = collections.Counter()
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(probe, p, a.req, a.pack): p for p in cands}
        done = 0
        for fut in cf.as_completed(futs):
            p = futs[fut]
            out, detail = fut.result()
            tally[out] += 1
            done += 1
            if out == "route":
                hits.append((p, detail))
                print("  [%3d/%3d] RESOLVES  %-40s  %s" % (done, len(cands), p, detail))
            elif out == "error":
                print("  [%3d/%3d] error     %-40s  %s" % (done, len(cands), p, detail))
            if done % 25 == 0:
                print("  ... %d/%d" % (done, len(cands)))

    print("\nsummary: %s" % dict(tally))
    if not hits:
        print("\nno candidate resolved. Every one answered 14, which is what an")
        print("unknown route does -- so none of these is a real route.")
        print("Do not conclude anything from a single pass: the endpoint has a")
        print("~0.7%% transient, so re-run with --repeat 5 before ruling out.")
        return 1

    print("\nCONFIRM each hit with >=5 samples before trusting it:")
    for p, _d in hits:
        print("    python kgs_call.py --path %r --req '%s' --samples 5" % (p, a.req))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
