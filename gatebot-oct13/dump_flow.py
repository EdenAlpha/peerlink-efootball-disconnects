#!/usr/bin/env python3
"""dump_flow.py -- THE ground-truth tool: the real client's gate traffic,
in order, decrypted, with full request and response bodies.

WHY THIS EXISTS
---------------
Every other approach to this protocol is inference:
  * reading libUE4.so in Ghidra gives field NAMES but not the order, not the
    values, and not which of two ctor objects is the request builder;
  * guessing a command and firing it at the live gate costs a ~7 minute run
    and tells you only whether that one command was legal in that one state;
  * the passthrough captures in peerlink-efootball-disconnects are
    internet-side bytes only, with the gate still encrypted inside them.

But the encryption is not a barrier, because we already hold the key: the
same `gate_client` module chain3 uses to *speak* to the gate can *decode*
what the real client said.  mint.py already relies on this
(`gc.decode(reqs["CMD_CREATE_USER"])`) to reproduce account creation exactly.

corpus/flows.log is the raw recording: one `### REQ` / `### RESP` block per
gate call, hex-encoded.  This script parses it, decrypts every block, and
prints the flow as it actually happened -- which is the answer to "what is
the proper order and the proper request contents".

USAGE
    python dump_flow.py                  every block, full bodies
    python dump_flow.py --names          ordered command list only
    python dump_flow.py --cmd CREATE_USER   just that command, both sides
    python dump_flow.py --cmd CREATE_USER --raw   its undecoded hex too
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\kgs-gate-cipher")

import gate_client as gc  # noqa: E402

FLOWS = (r"C:\Users\Administrator\Documents\Default Project"
         r"\kgs-gate-cipher\corpus\flows.log")

REQ_LINE = re.compile(r"^### REQ POST (\S+)")
RESP_LINE = re.compile(r"^### RESP POST (\S+) -> (\d+)")
HOST_LINE = re.compile(r"^HOST: (\S+)")
HEX_LINE = re.compile(r"^(REQHEX|RESPHEX|REQLEN|RESPLEN): (.*)$")


def parse(path):
    """-> list of dicts {cmd, path, host, status, req_hex, resp_hex}"""
    blocks = []
    cur = None
    side = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            m = REQ_LINE.match(line)
            if m:
                cur = {"path": m.group(1), "host": None, "status": None,
                       "req_hex": None, "resp_hex": None}
                cur["cmd"] = _cmd_of(cur["path"])
                blocks.append(cur)
                side = "req"
                continue
            m = RESP_LINE.match(line)
            if m:
                # a RESP always belongs to the REQ that preceded it
                if cur is not None:
                    cur["status"] = int(m.group(2))
                    if _cmd_of(m.group(1)):
                        cur["cmd"] = _cmd_of(m.group(1))
                side = "resp"
                continue
            m = HOST_LINE.match(line)
            if m and cur is not None:
                cur["host"] = m.group(1)
                continue
            m = HEX_LINE.match(line)
            if m and cur is not None:
                key, val = m.group(1), m.group(2).strip()
                if key == "REQHEX" and side == "req":
                    cur["req_hex"] = val
                elif key == "RESPHEX" and side == "resp":
                    cur["resp_hex"] = val
    return blocks


def _cmd_of(path):
    """'/pes22/gate/gate_CMD_CREATE_USER.php' -> 'CMD_CREATE_USER'"""
    if not path:
        return None
    m = re.search(r"gate_(CMD_[A-Z0-9_]+)\.php", path)
    return m.group(1) if m else None


def decode(hexstr):
    """Decrypt one hex blob.  Returns (text, note)."""
    if not hexstr:
        return None, "no data"
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError as e:
        return None, "bad hex: %s" % e
    for candidate in (hexstr, raw):
        try:
            out = gc.decode(candidate)
        except Exception:                                  # noqa: BLE001
            continue
        if out is None:
            continue
        if isinstance(out, (dict, list)):
            return out, None
        if isinstance(out, (bytes, bytearray)):
            try:
                return json.loads(out.decode("utf-8")), None
            except Exception:                              # noqa: BLE001
                return out.decode("utf-8", "replace"), None
        if isinstance(out, str):
            s = out.strip()
            if s.startswith("{") or s.startswith("["):
                try:
                    return json.loads(s), None
                except Exception:                          # noqa: BLE001
                    pass
            return out, None
    return None, "decode() returned nothing usable"


def emit(obj, indent=4):
    return json.dumps(obj, indent=indent, ensure_ascii=False, default=str)


def main():
    argv = sys.argv[1:]
    if not os.path.exists(FLOWS):
        print("flows.log not found: %s" % FLOWS)
        return 1
    blocks = parse(FLOWS)

    if "--names" in argv:
        print("the real client's gate sequence, in order (%d calls):\n"
              % len(blocks))
        for i, b in enumerate(blocks, 1):
            print("%3d. %-42s %s" % (i, b["cmd"] or "(non-gate)",
                                     b["path"]))
        return 0

    want = None
    if "--cmd" in argv:
        i = argv.index("--cmd")
        if i + 1 < len(argv):
            want = argv[i + 1].upper()
            if not want.startswith("CMD_"):
                want = "CMD_" + want

    shown = 0
    for i, b in enumerate(blocks, 1):
        if want and b["cmd"] != want:
            continue
        shown += 1
        print("=" * 72)
        print("%3d. %s" % (i, b["cmd"] or b["path"]))
        print("     POST %s" % b["path"])
        if b["host"]:
            print("     host: %s" % b["host"])
        if b["status"] is not None:
            print("     status: %s" % b["status"])

        rq, rqerr = decode(b["req_hex"])
        if rqerr:
            print("     REQUEST  : %s" % rqerr)
        elif rq is not None:
            print("     REQUEST")
            print(emit(rq))

        rs, rserr = decode(b["resp_hex"])
        if rserr:
            print("     RESPONSE : %s" % rserr)
        elif rs is not None:
            print("     RESPONSE")
            print(emit(rs))

        if "--raw" in argv:
            if b["req_hex"]:
                print("     REQHEX: %s" % b["req_hex"])
            if b["resp_hex"]:
                print("     RESPHEX: %s" % b["resp_hex"])
        print()

    if want and not shown:
        print("no block for %s.  Commands present:" % want)
        for b in blocks:
            if b["cmd"]:
                print("   %s" % b["cmd"])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
