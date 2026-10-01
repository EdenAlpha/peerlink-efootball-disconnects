#!/usr/bin/env python3
"""Decode gate responses captured by mitm_addon.py.

Why this exists
---------------
TLS being terminated is not the same as a body being readable. Two different
layers are in play:

  * the gate transport is HTTPS, so the proxy can read it -- that part works.
  * the request and response BODIES are additionally encrypted by the game
    itself. Measured on 2026-10-01: the login request body is 608 bytes at
    Shannon entropy 7.67 and the response 13712 bytes at 7.99, where readable
    JSON sits near 4.5. High entropy means ciphertext.

So this script does not assume either answer. It decodes every captured
response body and reports, per body, the length, the printable ratio and the
Shannon entropy, then prints the decoded bytes when the ratio says there is
something to read. Bodies that are genuinely ciphertext are reported as such
rather than being mangled into the output, because "this one is unreadable" is
itself the useful result.

Some responses are configuration rather than secrets -- server environment,
product list, relay quality -- and those turn out to be plaintext. That is the
point of running it over everything rather than only the login.

Usage:
    python3 decode_gate_flows.py [flows.log]
    python3 decode_gate_flows.py flows.log --json

The default input is the path the live workflow writes.
"""
from __future__ import annotations

import argparse
import binascii
import json
import math
import re
import sys
from collections import Counter

DEFAULT = "/tmp/kgs/flows.log"

# A body over this entropy is treated as ciphertext rather than text.
ENTROPY_TEXT_CEILING = 7.0
PRINTABLE_FLOOR = 0.60


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


def parse(text: str) -> list:
    """Split the flat log back into flows.

    The addon writes one flat stream with `### ` starting each flow, so the
    header line identifies the flow and the REQHEX/RESPHEX lines carry bytes.
    """
    flows = []
    cur = None
    for line in text.splitlines():
        if line.startswith("### "):
            if cur:
                flows.append(cur)
            kind = "REQ" if " REQ " in line else "RESP"
            cur = {"kind": kind, "head": line[4:].strip(), "hex": "", "host": ""}
            continue
        if cur is None:
            continue
        if line.startswith(("REQHEX:", "RESPHEX:")):
            cur["hex"] = line.split(":", 1)[1].strip()
        elif line.startswith("HOST:"):
            cur["host"] = line.split(":", 1)[1].strip()
    if cur:
        flows.append(cur)
    return flows


def describe(f: dict) -> dict:
    raw = b""
    if f["hex"]:
        try:
            raw = binascii.unhexlify(f["hex"])
        except (binascii.Error, ValueError) as exc:
            return {"head": f["head"], "error": "bad hex: %s" % exc}
    return {
        "head": f["head"],
        "host": f["host"],
        "len": len(raw),
        "entropy": round(shannon(raw), 2),
        "printable": round(printable_ratio(raw), 2),
        "raw": raw,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?", default=DEFAULT)
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    ap.add_argument("--show", type=int, default=700, help="bytes of text to print")
    args = ap.parse_args()

    try:
        with open(args.log, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print("cannot read %s: %s" % (args.log, exc), file=sys.stderr)
        return 1

    flows = [f for f in parse(text) if f["kind"] == "RESP"]
    if not flows:
        print("no RESP blocks in %s" % args.log)
        return 1

    summary = []
    for f in flows:
        d = describe(f)
        raw = d.pop("raw", b"")
        readable = (
            d.get("printable", 0) >= PRINTABLE_FLOOR
            and d.get("entropy", 99) <= ENTROPY_TEXT_CEILING
        )
        d["readable"] = readable
        summary.append(d)

        if args.json:
            continue
        print("=" * 72)
        print(d["head"])
        if d.get("host"):
            print("  host      %s" % d["host"])
        if "error" in d:
            print("  %s" % d["error"])
            continue
        print(
            "  len %d  entropy %.2f  printable %.0f%%  -> %s"
            % (
                d["len"],
                d["entropy"],
                d["printable"] * 100,
                "TEXT" if readable else "CIPHERTEXT",
            )
        )
        if readable:
            body = raw.decode("utf-8", "replace")
            print("  " + body[: args.show].replace("\n", "\n  "))

    if args.json:
        print(json.dumps(summary, indent=2))

    n_read = sum(1 for d in summary if d["readable"])
    print("=" * 72)
    print("%d/%d response bodies readable as text" % (n_read, len(summary)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
