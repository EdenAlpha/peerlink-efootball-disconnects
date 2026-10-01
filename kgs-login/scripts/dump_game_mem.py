#!/usr/bin/env python3
"""Dump a running app's writable memory off an Android device and search it.

Why this exists
---------------
frida-server cannot inject into this redroid image. Reproduced on two major
lines -- 17.19.0 and 16.7.19 -- both dying at the injection step with
"Failed to spawn: connection closed" and frida.out reporting
"Aborted (core dumped)", on spawn and on attach alike. So the usual route of
reading the app's own pre-encryption bytes is unavailable.

This is the fallback that needs no injector at all. The game builds the request
body in memory and only then encrypts it, so the plaintext exists in its heap
while it runs. Reading /proc/<pid>/mem requires no ptrace *injection*, only
permission to open the file, and the container has root via `su 0`.

The plaintext markers searched for are strings the game must hold:

  CMD_LOGIN, CMD_GET_SESSION_ID, CMD_CREATEJOIN_ROOM, CMD_GET_ROOM_INFO
      command names, which appear in the request the app assembles
  /pes22/gate/
      the gate prefix
  NOERR, "result"
      the response envelope keys seen in decoded CommandResponse bodies

Finding any of these in the writable regions proves the approach works and
gives the plaintext request body directly.

The device has no python, so all parsing happens here on the host. Memory is
read with `dd` using page-aligned bs/skip/count so no byte-offset arithmetic is
needed, then pulled and scanned.

Usage:
    python3 dump_game_mem.py [package] [--serial S] [--top 12] [--out DIR]
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys

MARKERS = [
    b"CMD_LOGIN",
    b"CMD_GET_SESSION_ID",
    b"CMD_CREATEJOIN_ROOM",
    b"CMD_GET_ROOM_INFO",
    b"CMD_SEND_RECRUIT_CODE",
    b"/pes22/gate/",
    b"command_service",
    b"CommandStream",
    b"NOERR",
    b"packMode",
]


def adb(serial: str, *args: str, timeout: int = 120) -> str:
    cmd = ["adb", "-s", serial, *args]
    try:
        out = subprocess.run(
            cmd, capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return ""
    return out.stdout.decode("utf-8", "replace")


def shell_root(serial: str, script: str, timeout: int = 300) -> str:
    """Run a command on the device as root.

    Passed as ONE argument to `adb shell`, because adb joins its own argv with
    spaces before the device shell sees it. Passing them separately arrived as

        su 0 sh -c cat /proc/18731/maps

    where `sh -c cat` runs the single word "cat" with the path as $0: empty
    output, indistinguishable from a permissions failure.

    There is deliberately no `sh -c` layer. `su 0 <cmd>` works, and adding
    `sh -c` on top of it returns nothing on this image. So scripts must avoid
    shell metacharacters -- no pipes, no redirection -- which is why the dd
    call below redirects its own stderr on the device instead of piping it
    through tail.
    """
    if any(ch in script for ch in "|<>&;"):
        return adb(serial, "shell", "su 0 sh -c \"%s\"" % script, timeout=timeout)
    return adb(serial, "shell", "su 0 " + script, timeout=timeout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("package", nargs="?", default="jp.konami.pesam")
    ap.add_argument("--serial", default="127.0.0.1:5555")
    ap.add_argument("--top", type=int, default=12,
                    help="how many of the largest writable regions to dump")
    ap.add_argument("--out", default="/tmp/kgs/memdump")
    args = ap.parse_args()

    if shutil.which("adb") is None:
        print("adb not on PATH", file=sys.stderr)
        return 1

    pid = adb(args.serial, "shell", "pidof", args.package).strip()
    if not pid:
        print("package %s is not running" % args.package)
        return 1
    print("pid %s" % pid)

    maps = shell_root(args.serial, "cat /proc/%s/maps" % pid)
    if not maps or "cat:" in maps.splitlines()[0]:
        print("cannot read maps as root:\n%s" % maps[:400])
        return 1
    lines = maps.splitlines()
    print("%d map lines" % len(lines))

    regions = []
    for ln in lines:
        m = re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)$", ln)
        if not m:
            continue
        start, end, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
        if "w" not in perms:
            continue
        size = end - start
        if size < 256 * 1024:          # skip tiny regions
            continue
        regions.append((size, start, end, perms, name.strip()))
    regions.sort(reverse=True)
    print("%d writable regions over 256K; taking the largest %d"
          % (len(regions), args.top))

    os.makedirs(args.out, exist_ok=True)
    dumped = 0
    hits = {}

    for size, start, end, perms, name in regions[: args.top]:
        npages = (end - start) // 4096
        remote = "/data/local/tmp/memdump.bin"
        label = "%012x-%012x %s %s" % (start, end, perms, name or "[anon]")
        # Read page-aligned so dd needs no byte offsets.
        got = shell_root(
            args.serial,
            "dd if=/proc/%s/mem of=%s bs=4096 skip=%d count=%d 2>/data/local/tmp/dd.err"
            % (pid, remote, start // 4096, npages),
            timeout=600,
        )
        err = shell_root(args.serial, "cat /data/local/tmp/dd.err")
        if "denied" in err or "ermission" in err or "ermission" in got:
            print("  SKIP %s -> %s" % (label, (err or got).strip()[:90]))
            continue
        local = os.path.join(args.out, "region_%012x.bin" % start)
        rc = subprocess.run(
            ["adb", "-s", args.serial, "pull", remote, local],
            capture_output=True,
        )
        if rc.returncode != 0 or not os.path.exists(local):
            print("  PULL FAILED %s" % label)
            continue
        dumped += 1
        try:
            with open(local, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            print("  READ FAILED %s: %s" % (label, exc))
            continue
        found = [mk for mk in MARKERS if mk in blob]
        print("  %s  %.1f MB  markers: %s"
              % (label, len(blob) / 1048576.0,
                 ", ".join(m.decode() for m in found) or "none"))
        for mk in found:
            hits.setdefault(mk, []).append((local, blob))

    shell_root(args.serial, "rm -f /data/local/tmp/memdump.bin")

    print("=" * 70)
    print("dumped %d regions" % dumped)
    if not hits:
        print("no markers found. The app-layer plaintext may be built in a "
              "region not dumped, or the strings may be stored obfuscated.")
        return 2

    for mk, found in hits.items():
        local, blob = found[0]
        idx = blob.find(mk)
        lo, hi = max(0, idx - 400), min(len(blob), idx + 900)
        print("=" * 70)
        print("MARKER %s in %s at 0x%x" % (mk.decode(), local, idx))
        chunk = blob[lo:hi]
        # Show only the printable runs so the ciphertext around it is not noise.
        for run in re.findall(rb"[\x20-\x7e]{6,}", chunk):
            print("   ", run.decode("ascii", "replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
