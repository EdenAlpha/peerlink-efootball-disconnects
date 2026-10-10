#!/usr/bin/env python3
"""Trace who reads grpc_heartbeat_interval_msec, and the call chain above it.

The string lives in .data (offset 0x98facc0, vaddr 0x9906cc0), so code
reaches it through a pointer table rather than ADRP. This script:
  1. finds pointers to the string in .data.rel.ro / .data
  2. finds code that loads those pointers
  3. ascends the BL call graph to a top-level task

Section map (read from the ELF header):
  .rodata       off 0x725800   vaddr 0x725800     (identity)
  .text         off 0x28253c0  vaddr 0x28293c0
  .data.rel.ro  off 0x8b6d140  vaddr 0x8b75140
  .data         off 0x98facc0  vaddr 0x9906cc0
"""
from __future__ import annotations

import struct
import sys
from collections import defaultdict

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib"
      r"\arm64-v8a\libUE4.so")

TEXT_OFF, TEXT_VADDR, TEXT_SIZE = 0x28253C0, 0x28293C0, 0x630BE48
RELRO_OFF, RELRO_VA, RELRO_SIZE = 0x8B6D140, 0x8B75140, 0xD48748
DATA_OFF, DATA_VA, DATA_SIZE = 0x98FACC0, 0x9906CC0, 0x63D84

KEYS = [
    (0x98FADD, "grpc_heartbeat_interval_msec"),   # file offset in .data
    (0x9C69DD, "grpc_heartbeat_interval_msec(?)"),  # rodata copy
    (0xA71FB0, "CMD_HEARTBEAT_GRPC"),
    (0xA7252E, "CMD_FINISHED_COUNT_GRPC"),
]


def adrp(i, pc):
    if (i & 0x9F000000) != 0x90000000:
        return None
    v = (((i >> 5) & 0x7FFFF) << 2) | ((i >> 29) & 3)
    if v & (1 << 20):
        v -= 1 << 21
    return (pc & ~0xFFF) + (v << 12), i & 0x1F


def add_imm(i):
    if (i & 0xFF800000) != 0x91000000:
        return None
    return i & 0x1F, (i >> 5) & 0x1F, (i >> 10) & 0xFFF


def main() -> int:
    d = open(SO, "rb").read()

    text = d[TEXT_OFF:TEXT_OFF + TEXT_SIZE]

    # BL call graph
    print("building call graph ...", flush=True)
    callers = defaultdict(list)
    n = len(text) // 4
    for idx in range(n):
        insn = struct.unpack_from("<I", text, idx * 4)[0]
        if (insn & 0xFC000000) != 0x94000000:
            continue
        imm = insn & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        pc = TEXT_VADDR + idx * 4
        callers[pc + (imm << 2)].append(pc)
    print(f"  {len(callers)} call targets", flush=True)

    # ADRP index: page -> list of (pc, rd)
    print("indexing ADRP ...", flush=True)
    adrp_by_page = defaultdict(list)
    for idx in range(n):
        insn = struct.unpack_from("<I", text, idx * 4)[0]
        r = adrp(insn, TEXT_VADDR + idx * 4)
        if r:
            adrp_by_page[r[0]].append((r[1], TEXT_VADDR + idx * 4))

    def ascend(va, depth=8):
        cur = va
        for _ in range(depth):
            sites = callers.get(cur, [])
            if not sites:
                print(f"      {'  ' * _}^ {cur:#x} <- (top/indirect)")
                return
            print(f"      {'  ' * _}^ {cur:#x} <- "
                  f"{', '.join(hex(s) for s in sites[:4])}")
            cur = sites[0]

    for file_off, name in KEYS:
        print(f"\n{'=' * 70}\n{name}  file off {file_off:#x}\n{'=' * 70}")
        va = file_off
        page = va & ~0xFFF
        off_in_page = va - page
        print(f"  page {page:#x}  off-in-page {off_in_page:#x}")
        sites = adrp_by_page.get(page, [])
        print(f"  ADRP sites loading this page: {len(sites)}")
        # pair ADRP with a later ADD using the same rd (window of 12 insns)
        for rd, pc in sites[:40]:
            idx = (pc - TEXT_VADDR) // 4
            for k in range(1, 12):
                if idx + k >= n:
                    break
                insn = struct.unpack_from("<I", text, (idx + k) * 4)[0]
                a = add_imm(insn)
                if a and a[1] == rd and a[0] == rd:
                    if a[2] == off_in_page:
                        print(f"    ADRP+ADD hit at {pc:#x} -> {va:#x} "
                              f"(+{k} insns)")
                        ascend(pc)
                    break
                # stop early if the register is overwritten by another ADRP
                r2 = adrp(insn, TEXT_VADDR + (idx + k) * 4)
                if r2 and r2[1] == rd:
                    break

    return 0


if __name__ == "__main__":
    sys.exit(main())
