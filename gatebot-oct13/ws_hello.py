#!/usr/bin/env python3
"""ws_hello.py -- relay conversation: version exchange then registers.

Per connection: recv server hello (00 01), reply with our version,
then push one candidate register payload.  All frames printed hex +
decoded (redacted).
"""
import json
import struct
import sys

import msgpack

from ws_session import (NAME, TOKEN, SID, SIDE, ws_connect, ws_send,
                        ws_recv_frames, describe_frame, redact)


def conv(label, after_version, version_reply=b"\x00\x01",
         version_binary=True, wait_after_version=1.5, wait=4.0):
    try:
        s, initial = ws_connect()
    except OSError as e:
        print("  %-16s connect: %s" % (label, e))
        return
    frames, _ = ws_recv_frames(s, initial, 2.0)
    print("  %-16s server: %s" % (label, [
        describe_frame(o, p) for o, p in frames] or "silence"))
    if version_reply is not None:
        ws_send(s, version_reply, version_binary)
        f2, _ = ws_recv_frames(s, b"", wait_after_version)
        print("  %-16s after version: %s" % (label, [
            describe_frame(o, p) for o, p in f2] or "silence"))
    if after_version is not None:
        payload, binary = after_version
        ws_send(s, payload, binary)
        f3, closed = ws_recv_frames(s, b"", wait)
        print("  %-16s after payload: %s%s" % (label, [
            describe_frame(o, p) for o, p in f3],
            " (closed)" if closed else ""))
    s.close()


def main():
    modes = sys.argv[1:] or ["all"]
    print("== version only ==")
    conv("version-only", None, wait_after_version=4.0)
    if "mp1" in modes or "all" in modes:
        conv("ver+mpack{name,tok}",
             (msgpack.packb({"name": NAME, "token": TOKEN}), True))
    if "js1" in modes or "all" in modes:
        conv("ver+json{name,tok}",
             (json.dumps({"name": NAME, "token": TOKEN}).encode(), False))
    if "ar" in modes or "all" in modes:
        conv("ver+mpack[name,tok]", (msgpack.packb([NAME, TOKEN]), True))
    if "raw" in modes or "all" in modes:
        conv("ver+raw name", (NAME.encode(), True))
    if "mp2" in modes or "all" in modes:
        conv("ver+mpack sid,tok",
             (msgpack.packb({"sid": SID, "token": TOKEN}), True))
    if "js2" in modes or "all" in modes:
        conv("ver+json full",
             (json.dumps({"name": NAME, "sid": SID, "token": TOKEN,
                          "side": SIDE}).encode(), False))
    if "nover" in modes:
        conv("no-version json", (json.dumps(
            {"name": NAME, "token": TOKEN}).encode(), False),
            version_reply=None)


if __name__ == "__main__":
    main()
