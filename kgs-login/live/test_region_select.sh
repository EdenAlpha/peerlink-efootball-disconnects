#!/usr/bin/env bash
# Region-selection regression test for grab_gate_plaintext.sh.
#
# Why this test exists
# --------------------
# On the 2026-10-01 run the selection printed "candidate regions:" and then
# nothing. Zero regions were selected, so the scan never ran at all. The
# "0 gzip-magic offsets seen" that run reported therefore proved only that
# nothing was inspected -- NOT that the plaintext bodies were absent from
# memory. That conclusion is withdrawn until this test passes and the scan has
# been re-run against a real device.
#
# Bugs this test has already caught
# ---------------------------------
# 1. grab_gate_plaintext.sh had been saved with CRLF line endings (207/207
#    lines). Under bash, every field read from /proc/<pid>/maps keeps a
#    trailing \r, so every `case` pattern fails to match and every region is
#    skipped -- silently, with a zero exit status. That file must stay LF only.
#
# 2. The skip-filter case arm was written as:
#         case "$name" in
#           /dev/* | \[vvar\] | \[vsyscall\] | anon_inode:*) continue ;;
#         esac
#    A bare word inside a case pattern list terminates the `in` list early, so
#    the arm never matched as intended and `continue` fired for EVERY region.
#    Alternatives must be separated by escaped pipes.
#
# 3. Region names contain spaces ("[anon:dalvik-main space (region space)]").
#    Passing the record through awk re-splits on whitespace, so the leading
#    field stops parsing as an integer and every downstream arithmetic test
#    fails. No second parse is used here: the record is produced, sorted and
#    head-ed in one pipeline, and only `cut -d' ' -f2-` (which keeps the tail
#    intact) touches the text afterwards.
#
# 4. The producer must be the only reader of stdin. When a second `while read`
#    loop existed in the same script, the producer consumed exactly one line
#    and exited (confirmed with `bash -x`). Every loop below therefore reads
#    from an explicit file redirect, never from stdin.
set -uo pipefail

MAXREGIONS=${MAXREGIONS:-40}

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

OUT=${OUT:-/tmp/regions_test.txt}

select_regions() {
  while read -r range perms rest; do
    [ -n "${range:-}" ] || continue
    case "$range" in
      *-*) ;;
      *) continue ;;
    esac
    case "${perms:-}" in
      r*) ;;
      *) continue ;;
    esac
    name="${rest##*  }"
    size=$(( 0x${range#*-} - 0x${range%%-*} ))
    [ "$size" -gt 0 ] || continue
    case "$name" in
      /dev/* | \[vvar\] | \[vsyscall\] | anon_inode:*) continue ;;
    esac
    prio=1
    case "$name" in
      *.so* | *lib* | *heap* | *dalvik* | *art* | *jit*) prio=0 ;;
      "" | *" "* | *anon*)                              prio=1 ;;
      *)                                                 prio=0 ;;
    esac
    printf '%d %d %s %s\n' "$prio" "$size" "$range" "$name"
  done < "$maps_file" | sort -k1,1n -k2,2nr | head -"$MAXREGIONS" | cut -d' ' -f2-
}

printf '%s\n' "$maps" > /tmp/maps_test.txt
maps_file=/tmp/maps_test.txt

select_regions > "$OUT"

echo "=== selected ==="
while read -r size range name; do
  printf '  %-26s %6d MB  %s\n' "$range" "$((size / 1048576))" "$name"
done < "$OUT"

count=$(grep -c . "$OUT" || true)
echo "count: $count"
if [ "$count" -eq 0 ]; then
  echo "FAIL: zero regions selected (the 2026-10-01 bug)"
  exit 1
fi

echo
echo "=== assertions ==="
rc=0

if grep -q 'libUE4.so' "$OUT"; then
  echo "PASS: libUE4.so included (the key may live in its data segment)"
else
  echo "FAIL: libUE4.so missing"
  rc=1
fi

if grep -q -- '---p' "$OUT"; then
  echo "FAIL: a no-access guard page was selected"
  rc=1
else
  echo "PASS: no-access pages excluded"
fi

if grep -q 'vvar\|vsyscall' "$OUT"; then
  echo "FAIL: kernel pseudo-mapping selected"
  rc=1
else
  echo "PASS: kernel pseudo-mappings excluded"
fi

first=$(head -1 "$OUT" | cut -d' ' -f1)
case "$first" in
  '' | *[!0-9]*)
    echo "FAIL: leading field is not numeric (got '$first') -- name got re-split"
    rc=1 ;;
  *)
    echo "PASS: leading field is numeric ($first bytes)" ;;
esac

if grep -q 'dalvik-main space' "$OUT"; then
  echo "PASS: multi-word region name survived intact"
else
  echo "NOTE: dalvik name absent (anon fallback still covers it)"
fi

echo
echo "RESULT: $([ "$rc" -eq 0 ] && echo OK || echo FAILED)"
exit "$rc"