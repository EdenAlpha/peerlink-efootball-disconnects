#!/usr/bin/env python3
"""Drive one KGS command_service session: log in, create a room, print its code.

This is the last piece of the chain. It only *calls* commands; it does not
decide what they are. Route names come from `kgs-login/routes.txt` and request
payloads come from `kgs-login/payloads/<STEP>.json`, so a route or a payload
recovered from the game's own traffic can be dropped in without touching code.

Photocopier principle: every byte on the wire is produced by `kgs_client`
(`command_request`, `frame`, `connect`), which was itself derived from the
protobuf descriptor embedded in libUE4.so. Nothing here re-implements framing
or protobuf, and no payload is invented -- a step with no payload file is sent
with `{}` and is reported as such.

Two things it deliberately cannot do, because they would be fabrications:

  * it does not synthesise a login `req` (device identity, Konami auth token,
    uid, libVer). That has to come from a real capture.
  * it does not guess a route. An unknown route comes back as grpc-status 14
    UNAVAILABLE -- the same 14 the load balancer renders as HTTP 502 -- and the
    script reports it and stops, rather than pretending it worked.

Usage:
    python kgs_session.py --dry-run          # print the exact bytes per step
    python kgs_session.py                    # run the chain for real
    python kgs_session.py --route CMD_LOGIN=payload.json --settle 12
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kgs_client as kc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROUTES_FILE = os.path.join(HERE, "..", "routes.txt")
PAYLOAD_DIR = os.path.join(HERE, "..", "payloads")

# Candidate order for a login-then-room session. These are NOT verified routes:
# every one of them must earn its place by returning something other than
# grpc-status 14. `routes.txt` overrides this list wholesale.
DEFAULT_ROUTES: List[str] = [
    "CMD_GET_SESSION_ID",
    "CMD_LOGIN",
    "CMD_CREATEJOIN_ROOM",
    "CMD_GET_ROOM_INFO",
    "CMD_SEND_RECRUIT_CODE",
]

# Where a recruit / join code plausibly hides in a response body. Used only to
# *extract* a value from a body the server already sent -- never to create one.
CODE_KEYS = ("recruitCode", "recruit_code", "joinCode", "join_code",
             "roomCode", "room_code", "code", "password")


def load_routes() -> List[Tuple[str, Optional[str]]]:
    """Return [(route, payload_override_or_None)].

    routes.txt format, one step per line:
        CMD_LOGIN                 # use payloads/CMD_LOGIN.json
        CMD_LOGIN=some.json       # use this file instead
    Blank lines and # comments ignored.
    """
    try:
        with open(ROUTES_FILE, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return [(r, None) for r in DEFAULT_ROUTES]

    steps: List[Tuple[str, Optional[str]]] = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" in line:
            route, payload = line.split("=", 1)
            steps.append((route.strip(), payload.strip()))
        else:
            steps.append((line, None))
    return steps or [(r, None) for r in DEFAULT_ROUTES]


def load_payload(route: str, override: Optional[str]) -> Tuple[str, str]:
    """Return (payload_text, provenance).

    Provenance is printed with every result so it is always visible whether the
    body was captured, supplied, or empty.
    """
    if override:
        path = override if os.path.isabs(override) else os.path.join(
            HERE, "..", "payloads", override)
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read().strip(), "file:" + os.path.basename(path)
        except FileNotFoundError:
            return "{}", "MISSING " + os.path.basename(path)

    path = os.path.join(PAYLOAD_DIR, route + ".json")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip(), "file:" + os.path.basename(path)
    except FileNotFoundError:
        return "{}", "empty"


def find_code(text: str) -> Optional[str]:
    """Pull a code out of a response body the server sent. Never invent one."""
    if not text:
        return None
    try:
        obj = json.loads(text)
    except Exception:
        return None

    def walk(node) -> Optional[str]:
        if isinstance(node, dict):
            for key in CODE_KEYS:
                val = node.get(key)
                if isinstance(val, (str, int)) and str(val).strip():
                    return str(val).strip()
            for val in node.values():
                got = walk(val)
                if got:
                    return got
        elif isinstance(node, list):
            for item in node:
                got = walk(item)
                if got:
                    return got
        return None

    return walk(obj)


class Session:
    """One CommandStream, kept open for the whole chain.

    CommandStream is bidirectional streaming, so a login is a *session*: the
    session id from step 1 has to arrive on the same stream that step 2 rides
    on. Opening a fresh connection per command, as kgs_client.call does, throws
    that away -- which is why this class exists rather than a loop over call().
    """

    # kgs_client.connect() opens the stream with HEADERS on stream 1, so every
    # DATA frame has to go out on stream 1 too. The CommandRequest.id field is
    # a separate uuid and is NOT the stream id -- conflating the two sends the
    # first request on an unopened stream and the server simply never replies.
    STREAM_ID = 1

    def __init__(self, settle: float):
        self.settle = settle
        self.sock = kc.connect()

    def send(self, path: str, payload: str, pack_mode: int = kc.PACK_JSON) -> bytes:
        """Send one CommandRequest; return the exact bytes sent."""
        msg = kc.command_request(self._request_id(), path, payload, pack_mode)
        grpc = b"\x00" + len(msg).to_bytes(4, "big") + msg
        self.sock.sendall(kc.frame(0, 0x1, self.STREAM_ID, grpc))
        return msg

    @staticmethod
    def _request_id() -> str:
        import uuid
        return str(uuid.uuid4())

    def recv(self, want: int = 1) -> Dict:
        return kc.read_frames(self.sock, self.settle, want)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


def status_of(frames: Dict) -> Tuple[str, str]:
    """(grpc-status, grpc-message) from the trailers, or ('-', '')."""
    st, msg = "-", ""
    for _flags, headers in frames.get("headers", []):
        if "grpc-status" in headers:
            st = headers["grpc-status"]
            msg = unquote_plus(headers.get("grpc-message", ""))
    return st, msg


def body_of(frames: Dict) -> str:
    """Decode the gRPC message payload into CommandResponse.res."""
    data = frames.get("data", b"")
    if len(data) < 5:
        return ""
    mlen = int.from_bytes(data[1:5], "big")
    body = data[5:5 + mlen]
    if not body:
        return ""
    return kc.command_response(body).get("res") or ""


def dry_run(steps) -> int:
    """Print the exact CommandRequest bytes per step, for diffing against a capture.

    This is how the script stays honest: whatever it would put on the wire is
    printed before anything is sent, so it can be compared byte for byte with a
    frame the real game produced.
    """
    print("dry run -- no connection made\n")
    for route, override in steps:
        payload, prov = load_payload(route, override)
        msg = kc.command_request("DRYRUN", route, payload, kc.PACK_JSON)
        print(f"{route}")
        print(f"  payload   {payload[:70]}{'...' if len(payload) > 70 else ''}")
        print(f"  from      {prov}")
        print(f"  request   {len(msg)} bytes: {msg.hex()}")
        print()
    return 0


def run(steps, settle: float, out_path: Optional[str]) -> int:
    print(f"{'STEP':<24} {'GRPC':<6} {'FROM':<14} RESULT")
    print("-" * 78)

    sess = Session(settle)
    code = None
    first_bad = None
    try:
        for idx, (route, override) in enumerate(steps, 1):
            payload, prov = load_payload(route, override)
            try:
                sent = sess.send(route, payload)
            except Exception as exc:  # connection died mid-chain
                print(f"{route:<24} {'ERR':<6} {prov:<14} {exc}")
                return 2

            frames = sess.recv()
            st, msg = status_of(frames)
            res = body_of(frames)

            if st == "14":
                # The whole 502/14 story: an unresolvable command. Report the
                # step name so the missing route is a one-line fix in
                # routes.txt rather than an open-ended hunt.
                print(f"{route:<24} {st:<6} {prov:<14} ROUTE NOT RECOGNISED"
                      f"{(' -- ' + msg[:60]) if msg else ''}")
                if first_bad is None:
                    first_bad = route
                break

            got = find_code(res)
            if got:
                code = got

            print(f"{route:<24} {st:<6} {prov:<14} "
                  f"{(res[:70] + '...') if len(res) > 70 else res}")

            if st == "-" and not res and idx == 1:
                print("\nno response on the first step -- the route is probably "
                      "wrong or the stream needs a longer settle. Try "
                      "--settle 15.")
                return 3
    finally:
        sess.close()

    print("-" * 78)
    if code:
        print(f"JOIN CODE: {code}")
        if out_path:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(code + "\n")
            print(f"written to {out_path}")
        return 0

    if first_bad:
        print(f"chain stopped at {first_bad}: the server does not know that "
              "route.")
        print("Add the real route to kgs-login/routes.txt and run again.")
        return 4

    print("chain completed but no join code appeared in any response.")
    print("Check CMD_GET_ROOM_INFO / CMD_SEND_RECRUIT_CODE bodies with --settle 15.")
    return 5


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the exact request bytes per step and exit")
    ap.add_argument("--route", action="append", default=[],
                    metavar="ROUTE[=FILE]",
                    help="override the route list; repeatable")
    ap.add_argument("--settle", type=float, default=8.0,
                    help="seconds to wait for each response")
    ap.add_argument("--out", metavar="FILE",
                    help="write the join code here on success")
    args = ap.parse_args()

    if args.route:
        steps = []
        for item in args.route:
            if "=" in item:
                route, payload = item.split("=", 1)
                steps.append((route.strip(), payload.strip()))
            else:
                steps.append((item.strip(), None))
    else:
        steps = load_routes()

    if args.dry_run:
        return dry_run(steps)
    return run(steps, args.settle, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
