#!/usr/bin/env python3
"""Find the code that drives the 15-second gRPC heartbeat.

Two questions:
  1. Who materialises CMD_HEARTBEAT_GRPC / CMD_FINISHED_COUNT_GRPC?
  2. What is the call chain that reaches them?

Follows pointer references (the cmd table stores pointers to string
objects, not the strings themselves) and BL call edges.
"""
from __future__ import annotations

import os
import struct
import sys
from collections import defaultdict

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib"
      r"\arm64-v8a\libUE4.so")

# Known code region (from xref_ptr.py): TEXT_OFF..TEXT_OFF+TEXT_SIZE
TEXT_OFF = 0x28253C0
TEXT_VADDR = 0x28293C0
TEXT_SIZE = 0x6000000

TARGETS = {
    0xA71FB0: "CMD_HEARTBEAT_GRPC",
    0xA7252E: "CMD_FINISHED_COUNT_GRPC",
    0x9C6961: "CMD_SEND_HEARTBEAT",
    0x9C69DD: "grpc_heartbeat_interval_msec",
    0x9DB2404: "CMD_CONNECT_GRPC",
}


def main() -> int:
    data = open(SO, "rb").read()

    def v2o(va: int) -> int:
        """vaddr -> file offset, using the known text mapping."""
        if TEXT_VADDR <= va < TEXT_VADDR + TEXT_SIZE:
            return va - TEXT_VADDR + TEXT_OFF
        return va  # rodata is identity-mapped in this build

    def o2v(off: int) -> int:
        if TEXT_OFF <= off < TEXT_OFF + TEXT_SIZE:
            return off - TEXT_OFF + TEXT_VADDR
        return off

    # ---- 1. pointer references to the string addresses ----------------
    print("=" * 74)
    print("POINTER REFERENCES (8-byte and 4-byte immediates)")
    print("=" * 74)
    refs: dict[int, list[int]] = {}
    for va in TARGETS:
        locs: list[int] = []
        for pat in (struct.pack("<Q", va), struct.pack("<I", va)):
            off = 0
            while True:
                i = data.find(pat, off)
                if i < 0:
                    break
                locs.append(i)
                off = i + 1
        seen: set[int] = set()
        uniq = []
        for off in sorted(locs):
            if any(abs(off - p) < 4 for p in uniq):
                continue
            uniq.append(off)
            seen.add(off)
        refs[va] = uniq
        if uniq:
            where = ("code" if TEXT_OFF <= uniq[0] < TEXT_OFF + TEXT_SIZE
                     else "data")
            print(f"  {TARGETS[va]:<28} {va:#010x}: "
                  f"{len(uniq)} ref(s)  first={where}")
        else:
            print(f"  {TARGETS[va]:<28} {va:#010x}: NO pointer references "
                  f"(probably reached by adrp+add)")

    # ---- 2. build the BL call graph over .text ------------------------
    print("\nbuilding BL call graph over .text ...", flush=True)
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    n = len(text) // 4
    callers: dict[int, list[int]] = defaultdict(list)
    for idx in range(n):
        insn = struct.unpack_from("<I", text, idx * 4)[0]
        if (insn & 0xFC000000) != 0x94000000:
            continue
        imm = insn & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        pc = TEXT_VADDR + idx * 4
        callers[pc + (imm << 2)].append(pc)

    print(f"  {n} instructions, {len(callers)} distinct call targets\n",
          flush=True)

    # ---- 3. ascend from each data-ref's containing function -----------
    print("=" * 74)
    print("WHO TOUCHES THE HEARTBEAT STRINGS")
    print("=" * 74)
    for va, name in TARGETS.items():
        print(f"\n--- {name} ({va:#x}) ---")
        locs = refs.get(va, [])
        if not locs:
            print("   no pointer references found")
            continue
        for off in locs[:8]:
            v = o2v(off)
            print(f"   ref at off {off:#010x} (va {v:#x})")
            if not (TEXT_OFF <= off < TEXT_OFF + TEXT_SIZE):
                continue
            # find the enclosing function by scanning back for a prologue
            fn = None
            probe = off
            for back in range(0, 0x2000, 4):
                p = probe - back
                if p < TEXT_OFF:
                    break
                insn = struct.unpack_from("<I", data, p)[0]
                # stp x29,x30,[sp,#-imm]!  = 0xA9......FD
                if (insn & 0xFFC003FF) == 0xA98003FD:
                    fn = p
                    break
            if fn is None:
                print("      (no prologue found nearby)")
                continue
            fva = o2v(fn)
            print(f"      enclosing func ~{fva:#x}")
            for depth in range(6):
                sites = callers.get(fva, [])
                if not sites:
                    print(f"      {'  ' * depth}^ "
                          f"{fva:#x} <- (indirect / top)")
                    break
                print(f"      {'  ' * depth}^ {fva:#x} <- "
                      f"{', '.join(hex(s) for s in sites[:4])}")
                fva = sites[0]
    return 0


if __name__ == "__main__":
    sys.exit(main())
