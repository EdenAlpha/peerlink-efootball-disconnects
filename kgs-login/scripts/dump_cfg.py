"""Dump the game's online config block and the 4-entry env table from a live
headless core after the game's own registrars have populated them."""
from __future__ import annotations

import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

REGIONS = [
    ("config block", 0xA4AF000, 0x3000),
    ("env table (0xa4cff68)", 0xA4CFF00, 0x400),
    ("online cfg 0xa4b0000", 0xA4B0000, 0x4000),
    ("cfg tail 0xa4c0000", 0xA4C0000, 0x2000),
]


def strings(data, base, minlen=3):
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append((base + m.start(), m.group().decode("ascii", "replace")))
    return out


def main():
    from peerlink.online_client import OnlineCore, REGISTRARS  # noqa

    t0 = time.time()
    print("[dump] booting core...", flush=True)
    core = OnlineCore(verbose=False)
    print(f"[dump] up in {time.time()-t0:.1f}s", flush=True)

    ok = 0
    for fn in REGISTRARS:
        try:
            core.call(fn)
            ok += 1
        except Exception as e:
            print(f"  registrar {fn:#x}: {type(e).__name__} {str(e)[:70]}")
    print(f"[dump] {ok}/{len(REGISTRARS)} registrars ran\n")

    seen_global = set()
    for label, va, ln in REGIONS:
        data = bytes(core.uc.mem_read(core.base + va, ln))
        ss = strings(data, va)
        print(f"=== {label}  ({va:#x} +{ln:#x}) — {len(ss)} strings ===")
        for a, s in ss:
            if s in seen_global and len(s) < 6:
                continue
            seen_global.add(s)
            print(f"    {a:#011x}  {s!r}")
        print()

    # hex dump around the env table
    print("=== env table raw 0xa4cff40..0xa4d0040 ===")
    d = bytes(core.uc.mem_read(core.base + 0xA4CFF40, 0x100))
    for i in range(0, len(d), 16):
        row = d[i:i + 16]
        print(f"  {0xA4CFF40 + i:#011x}  "
              f"{' '.join(f'{b:02x}' for b in row)}  "
              f"{''.join(chr(b) if 32 <= b < 127 else '.' for b in row)}")

    if getattr(core, "_log", None):
        print("\nharness log (last 15):")
        for line in core._log[-15:]:
            print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
