#!/usr/bin/env bash
# FULL memory dump generator (runs on the RUNNER).
# Pulls /proc/<pid>/maps, computes 64-bit dd args locally, writes ONE device
# script with literal `dd ... seek=` commands that assemble a single full.bin
# plus an index, pushes it, runs it, then pulls the result.
#
# Nothing is skipped except kernel pseudo-mappings ([vvar], [vsyscall],
# vdso/vvar style, /dev/*, anon_inode). Every readable region lands in full.bin
# with its file offset recorded in index.txt, so offline analysis can slice by
# original address. Regions that fail to read are recorded with rc/first-error,
# never silently dropped.
set -uo pipefail
W=/tmp/kgs/full
mkdir -p "$W"
A="adb -s 127.0.0.1:5555"
PID=$($A shell pidof jp.konami.pesam 2>/dev/null | tr -d '\r' | awk '{print $1}')
[ -n "${PID:-}" ] || { echo "FULL: no game pid"; exit 1; }
echo "FULL: pid=$PID"
$A shell su 0 cat /proc/$PID/maps > "$W/maps.txt" 2>/dev/null
echo "FULL: map_lines=$(wc -l < "$W/maps.txt")"
D="$W/dump.sh"
{
  echo '#!/system/bin/sh'
  echo 'W=/data/local/tmp/full; mkdir -p $W; : > $W/index.txt; : > $W/errors.txt; : > $W/full.bin'
  echo "PID=$PID"
} > "$D"
# runner-side: emit one dd per readable region, output offset tracked in pages
page=0
n=0
skipped=0
while read -r range perms rest; do
  [ -n "${range:-}" ] || continue
  case "$range" in *-*) ;; *) continue ;; esac
  case "${perms:-}" in r*) ;; *) continue ;; esac
  name="$rest"
  case "$name" in
    /dev/*|*\[vvar\]*|*\[vsyscall\]*|*vdso*|*anon_inode:*) skipped=$((skipped+1)); continue ;;
  esac
  start="${range%-*}"; end="${range#*-}"
  size=$(( 0x$end - 0x$start ))
  [ "$size" -gt 0 ] || continue
  skip=$(( 0x$start / 4096 )); count=$(( size / 4096 ))
  [ "$count" -gt 0 ] || continue
  esc_name=$(printf '%s' "$name" | tr ' ' '_' | cut -c1-80)
  [ -z "$esc_name" ] && esc_name="anon"
  printf 'dd if=/proc/%s/mem of=$W/full.bin bs=4096 skip=%s count=%s seek=%s conv=notrunc 2>$W/e; rc=$?; echo "%s %s %s $((%s*4096)) %s" >> $W/index.txt; [ $rc -ne 0 ] && echo "%s rc=$rc $(head -1 $W/e)" >> $W/errors.txt; echo -n "."\n' \
    "$PID" "$skip" "$count" "$page" "$range" "$perms" "$esc_name" "$page" "$page" "$range" >> "$D"
  page=$(( page + count ))
  n=$(( n + 1 ))
done < "$W/maps.txt"
total_mb=$(( page * 4096 / 1048576 ))
echo "FULL: regions=$n skipped_pseudo=$skipped total_pages=$page total_MB=$total_mb"
echo "FULL: device script $(wc -l < "$D") lines"
$A push "$D" /data/local/tmp/full_dump.sh 2>&1 | tail -1
echo "FULL: running dump on device..."
$A shell su 0 sh /data/local/tmp/full_dump.sh 2>&1 | tr -d '\r' | tail -3
echo "FULL: device listing:"
$A shell ls -l /data/local/tmp/full/ 2>&1 | tr -d '\r'
echo "FULL: errors:"
$A shell cat /data/local/tmp/full/errors.txt 2>&1 | tr -d '\r' | head -10
echo "FULL: pulling full.bin + index..."
$A pull /data/local/tmp/full/full.bin "$W/full.bin" 2>&1 | tail -1
$A pull /data/local/tmp/full/index.txt "$W/index.txt" 2>&1 | tail -1
ls -l "$W/full.bin" "$W/index.txt"
echo "FULL: index head:"
head -5 "$W/index.txt"
echo "FULL: done"