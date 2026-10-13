#!/usr/bin/env python3
"""grpc_beat.py -- does the default route dispatch on the msgpack msgid?

The gRPC wall: only path="/", "" and " " resolve; "/" answers
CommandResponse{id="CMD_END_CONNECTION"}.  But every earlier payload on that
route was JSON "{}" with a random id -- a real MessagePack envelope carrying a
msgid was never sent.  The response's `id` is the server's dispatch oracle
(FINDINGS 2026-09-29), so:

  1. gate login (real uid/session) -> CMD_CONNECT_GRPC (gate HTTP, NOERR --
     the app's own bind call, never followed by a stream probe before)
  2. five samples: CommandRequest{id=uuid, packMode=MSGPACK,
     req=msgpack(envelope{msgid=CMD_HEARTBEAT_GRPC, interval=15000}), path="/"}

If the dispatcher reads req.msgid, the response id comes back
CMD_HEARTBEAT_GRPC instead of CMD_END_CONNECTION.  Five samples because the
endpoint has a measured ~0.7% transient (FINDINGS, "any claim needs five").
"""
from __future__ import annotations

import json
import sys
import time
import uuid

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

# msgpack must be imported BEFORE the kgs-login\scripts path is added: that
# directory holds an old msgpack.py stub that would shadow the real module.
import msgpack  # noqa: E402

from room1 import PACE, Gate, describe, login, load_capture  # noqa: E402

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project"
                   r"\peerlink-efootball-disconnects\kgs-login\scripts")
import kgs_client as kc  # noqa: E402


def _req_bytes(req_id: str, path: str, payload: bytes,
               pack: int = 1) -> bytes:
    """CommandRequest with a BINARY req (kgs_client.f_str only takes str)."""
    def s(n: int, v) -> bytes:
        b = v.encode() if isinstance(v, str) else bytes(v)
        return kc.varint(n << 3 | 2) + kc.varint(len(b)) + b
    return (s(1, req_id) + kc.f_varint(2, pack)
            + s(3, payload) + s(4, path))


def beat_call(path: str, payload: bytes, pack: int = kc.PACK_MSGPACK,
              rid: str | None = None) -> tuple[str, str, dict]:
    """One one-shot call; return (grpc-status, grpc-message, response)."""
    req_id = rid or str(uuid.uuid4())
    msg = _req_bytes(req_id, path, payload, pack)
    s = kc.connect()
    try:
        g = b"\x00" + len(msg).to_bytes(4, "big") + msg
        s.sendall(kc.frame(0, 0x1, 1, g))
        r = kc.read_frames(s, 4.0)
    finally:
        try:
            s.close()
        except Exception:                              # noqa: BLE001
            pass
    st, gm = "-", ""
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
            gm = h.get("grpc-message", "")
    dec = {}
    if len(r["data"]) >= 5:
        mlen = int.from_bytes(r["data"][1:5], "big")
        dec = kc.command_response(r["data"][5:5 + mlen])
    return st, gm, dec


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0

    reqs = load_capture()[0]
    g = Gate()
    ok, r = login(g, reqs)
    print("login        -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1

    time.sleep(PACE)
    r = g.send(g.envelope("CMD_CONNECT_GRPC"))
    print("bind (gate)  -> %s" % r.get("result"))

    m = g.envelope("CMD_HEARTBEAT_GRPC")
    m["heartbeat_interval_msec"] = 15000
    payload = msgpack.packb(m, use_bin_type=True)
    print("heartbeat envelope %dB, msgid=%s" % (len(payload), m["msgid"]))

    # axis selector:  --ctl-json  packMode=0 "{}"   (known-good control)
    #                  --ctl-mp    packMode=1 "{}"   (isolate packMode)
    #                  --id-sweep  packMode=0 path="/" id=CMD_* (dispatch?)
    #                  (default)   packMode=1 real msgpack envelope
    forced_rid = None
    if "--ctl-json" in sys.argv:
        payload, pack = b"{}", kc.PACK_JSON
        print("variant: packMode=0 payload='{}'")
    elif "--ctl-mp" in sys.argv:
        payload, pack = b"{}", kc.PACK_MSGPACK
        print("variant: packMode=1 payload='{}'")
    elif "--id-sweep" in sys.argv:
        payload, pack = b"{}", kc.PACK_JSON
        print("variant: id-field dispatch on path='/' (packMode=0)")
    elif "--hb-json" in sys.argv:
        payload = json.dumps({k: v for k, v in m.items()
                              if k != "msgid"}).encode()
        pack = kc.PACK_JSON
        forced_rid = "CMD_HEARTBEAT_GRPC"
        print("variant: heartbeat with real JSON envelope (%dB)" % len(payload))

    if "--id-sweep" in sys.argv:
        counts = {}
        for rid in ("CMD_HEARTBEAT_GRPC", "CMD_CONNECT_GRPC",
                    "CMD_GET_SESSION_ID"):
            for i in range(3):
                st, gm, dec = beat_call("/", payload, pack, rid)
                tag = "%s->%s" % (rid, dec.get("id"))
                counts[tag] = counts.get(tag, 0) + 1
                print("  id=%-24s s%d -> grpc=%s disp=%r res=%r %s"
                      % (rid, i + 1, st, dec.get("id"),
                         (dec.get("res") or "")[:140], gm[:50]))
                time.sleep(1.0)
        print("summary: %s" % json.dumps(counts))
        return 0

    counts: dict = {}
    for i in range(5):
        st, gm, dec = beat_call("/", payload, pack, forced_rid)
        tag = "%s/%s" % (dec.get("id"), st)
        counts[tag] = counts.get(tag, 0) + 1
        print("  sample %d -> grpc=%s disp=%r res=%r %s"
              % (i + 1, st, dec.get("id"),
                 (dec.get("res") or "")[:160], gm[:60]))
        time.sleep(1.0)

    print("summary: %s" % json.dumps(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
