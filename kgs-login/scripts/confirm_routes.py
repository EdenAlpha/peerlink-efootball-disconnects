#!/usr/bin/env python3
"""Confirm routes recovered from memory against the live endpoint.

A `path` read out of the game's heap by `scan_paths.js` is a *candidate*, not a
route. It passed a strict protobuf decode, which proves it is shaped like a
CommandRequest, not that the server recognises it. Only the endpoint can decide
that, and it decides unambiguously: an unknown route answers gRPC 14
(UNAVAILABLE, surfaced as HTTP 502) every time, while a real route answers with a
CommandResponse.

So this takes the scanner's output and asks, rather than assuming. That matters
because the alternative failure mode is quiet and expensive -- acting on a
plausible-looking path and reporting progress that was never real.

Two guards, both of which exist because of how this endpoint behaves:

  * every candidate is probed `--repeat` times (default 5) and has to resolve
    every single time. The endpoint has a measured ~0.7% transient (18/2711),
    so one sample is not a verdict in either direction.
  * a candidate that resolves but returns an error is reported separately from
    one that is simply unknown. Those mean different things: the first means the
    route exists and the payload is wrong, the second means the route is not
    real. Collapsing them would hide exactly the information needed to proceed.

Usage:
    python confirm_routes.py scan-paths.log
    python confirm_routes.py paths.txt --req '{"...":"..."}' --repeat 5
"""
from __future__ import annotations

import argparse
import collections
import os
import re
import sys
import time
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

# the scanner logs:  [scan] path="/room/create"  packMode=1  id="..."  req="..."
LOG_RE = re.compile(r"path=(\"(?:[^\"\\]|\\.)*\")")


def parse_log(path):
    """Pull candidate paths out of a scan_paths.js log."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = LOG_RE.search(ln)
            if not m:
                continue
            import json
            try:
                out.append(json.loads(m.group(1)))
            except Exception:
                pass
    return out


def one(path, payload, pack):
    """Classify a single probe: resolves / unknown / error / failed."""
    try:
        r = call(path, payload, pack, str(uuid.uuid4()), settle=3.0)
    except Exception as e:
        return "failed", "%s: %s" % (type(e).__name__, e)
    grpc, gmsg = None, ""
    http = None
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            grpc = h["grpc-status"]
            gmsg = unquote_plus(h.get("grpc-message", ""))
        if ":status" in h:
            http = h[":status"]
    d = r["data"]
    cmd, res = None, None
    if len(d) >= 5:
        mlen = int.from_bytes(d[1:5], "big")
        dec = command_response(d[5:5 + mlen])
        cmd, res = dec.get("id"), dec.get("res")
    if cmd:
        # a CommandResponse came back: the route exists. Note an error result
        # separately -- that is a real route with a wrong payload, which is
        # progress, not failure.
        kind = "resolves"
        detail = "cmd=%s res=%s" % (cmd, (res or "")[:100])
        if res and '"result"' in res and '"NOERR"' not in res:
            kind = "error"
        return kind, detail
    if grpc == "14":
        return "unknown", "grpc=14 (HTTP %s) %s" % (http, gmsg)
    return "unknown", "http=%s grpc=%s cmd=%s" % (http, grpc, cmd)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source", help="scan log, or a file of one path per line")
    ap.add_argument("--req", default="{}")
    ap.add_argument("--pack", type=int, default=0, choices=(0, 1))
    ap.add_argument("--repeat", type=int, default=5)
    a = ap.parse_args()

    cands = parse_log(a.source) if a.source.endswith(".log") else [
        ln.strip() for ln in open(a.source, encoding="utf-8",
                                  errors="replace") if ln.strip()]
    cands = list(dict.fromkeys(cands))
    if not cands:
        print("no candidate paths found in %s" % a.source)
        print("If the scan log shows passes but no 'path=' lines, the game")
        print("never held a CommandRequest in a scannable form -- check the")
        print("logcat in the report before assuming the route table is absent.")
        return 2

    print("confirming %d candidate(s) from %s, %d sample(s) each\n"
          % (len(cands), a.source, a.repeat))
    confirmed, partial = [], []
    for p in cands:
        kinds = collections.Counter()
        detail = ""
        for i in range(a.repeat):
            k, dsc = one(p, a.req, a.pack)
            kinds[k] += 1
            detail = dsc
            if i + 1 < a.repeat:
                time.sleep(0.4)
        good = kinds["resolves"] + kinds["error"]
        bad = kinds["unknown"] + kinds["failed"]
        verdict = ("CONFIRMED" if good == a.repeat
                   else "PARTIAL" if good else "not a route")
        print("  %-10s %-34s %s  [%s]"
              % (verdict, repr(p)[:34], detail,
                 ", ".join("%s=%d" % kv for kv in sorted(kinds.items()))))
        if good == a.repeat:
            confirmed.append(p)
        elif good:
            partial.append((p, kinds))

    print("\n" + "=" * 68)
    if confirmed:
        print("CONFIRMED ROUTES (%d) - these are real:" % len(confirmed))
        for p in confirmed:
            print("    %r" % p)
        print("\nNext: drive the login chain with the real payloads, e.g.")
        print("    python kgs_call.py --path %r --req '{...}' --samples 5"
              % confirmed[0])
    if partial:
        print("\nPARTIAL (%d) - resolved on some samples only. The endpoint has a")
        print("~0.7%% transient, so re-run these before drawing a conclusion:"
              % len(partial))
        for p, k in partial:
            print("    %r  %s" % (p, dict(k)))
    if not confirmed and not partial:
        print("NONE of the %d candidate(s) resolved %d/%d times each."
              % (len(cands), a.repeat, a.repeat))
        print("Every one behaved exactly like an unknown route (gRPC 14),")
        print("which is the deterministic answer for a route that does not")
        print("exist. These were not routes.")
    return 0 if confirmed else 1


if __name__ == "__main__":
    raise SystemExit(main())
