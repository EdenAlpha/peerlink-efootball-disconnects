#!/usr/bin/env bash
# Exercise the REAL selection block from grab_gate_plaintext.sh against a
# synthetic /proc/<pid>/maps, by sourcing the script's own logic with `maps`
# and `$OUT` pre-set. Verifies the fix where it actually ships.
set -uo pipefail

OUT=/tmp/sel_out
rm -rf "$OUT"; mkdir -p "$OUT"
MAXREGIONS=40

# Pull the real region-selection block out of the script and execute it.
src=/c/Users/Administrator/Documents/Default\ Project/peerlink-efootball-disconnects/kgs-login/live/grab_gate_plaintext.sh
say() { echo "[say] $*"; }

maps=$(cat <<'EOF'
7f0000-7f1000 rw-p 00000000 00:00 0                  [stack]
10000000-14000000 rw-p 00000000 00:00 0
7a00000000-7a20000000 rw-p 00000000 00:00 0          [anon:dalvik-main space (region space)]
7f3a0000000-7f3c0000000 r-xp 00000000 fd:01 12345   /data/app/~~/lib/arm64/libUE4.so
7f3c0000000-7f3c8000000 rw-p 00000000 fd:01 12345   /data/app/~~/lib/arm64/libUE4.so
7f0000000000-7f000400000 rw-s 00000000 00:00 0
7ffd0000-7ffd4000 rw-p 00000000 00:00 0
7f0000-7f1000 ---p 00000000 00:00 0                  [guard]
EOF
)

# Extract the selection block by line range.
#   start = the line that writes maps.txt
#   end   = the line whose pipeline terminates in `> "$OUT/regions.txt"`.
# Line 83 is a bare `: > "$OUT/regions.txt"` (a truncate, not the result), so
# the end anchor must include the preceding `cut`, not just the redirect.
start=$(grep -n '> "\$OUT/maps.txt"' "$src" | head -1 | cut -d: -f1)
end=$(grep -n 'cut .* -f2- > "\$OUT/regions.txt"' "$src" | head -1 | cut -d: -f1)
if [ -z "$start" ] || [ -z "$end" ]; then
  echo "FAIL: could not locate the selection block in the script"
  echo "  start=[$start] end=[$end]"
  exit 2
fi
sed -n "${start},${end}p" "$src" > "$OUT/block.sh"
echo "=== extracted block: lines $start-$end ($(wc -l < "$OUT/block.sh") lines) ==="
head -2 "$OUT/block.sh"
echo "  ..."
tail -2 "$OUT/block.sh"
echo

# Execute it verbatim.
# shellcheck disable=SC1090
. "$OUT/block.sh"

echo "=== resulting regions.txt ==="
cat "$OUT/regions.txt"
echo "rows: $(grep -c . "$OUT/regions.txt" || true)"

rc=0
grep -q 'libUE4.so' "$OUT/regions.txt" || { echo "FAIL: no libUE4.so"; rc=1; }
grep -q -- '---p' "$OUT/regions.txt" && { echo "FAIL: guard page selected"; rc=1; }
[ "$(grep -c . "$OUT/regions.txt")" -gt 0 ] || { echo "FAIL: zero regions"; rc=1; }
head -1 "$OUT/regions.txt" | cut -d' ' -f1 | grep -qE '^[0-9]+$' \
  || { echo "FAIL: leading field not numeric"; rc=1; }

echo "RESULT: $([ "$rc" -eq 0 ] && echo OK || echo FAILED)"
exit "$rc"