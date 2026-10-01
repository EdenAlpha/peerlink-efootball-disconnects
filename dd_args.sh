#!/usr/bin/env bash
# Compute 64-bit dd arguments on the RUNNER (bash is 64-bit; Android's shell is
# not, and overflows a 52-bit address into a negative count).
#
# Symptom this fixes:
#   dd: -59839 < 0
# for libUE4.so regions at 0xf6abf1641000. Android sh does $(( )) in 32-bit, so
# 0xf6abf1641000/4096 wraps negative and dd refuses. Only sub-4GB regions
# (12c00000, 774fc000) ever worked -- which is why 8 of 10 dumps failed while the
# two that "succeeded" were the least interesting regions in the process.
#
# Output: one line per region with DECIMAL skip/count, to be embedded in the
# device script as literals so the device performs no arithmetic at all.
set -uo pipefail

while read -r range name; do
  [ -n "${range:-}" ] || continue
  start="${range%-*}"
  end="${range#*-}"
  skip=$(( 0x$start / 4096 ))
  count=$(( (0x$end - 0x$start) / 4096 ))
  printf '%s %s %s %s\n' "$skip" "$count" "$name" "$range"
done