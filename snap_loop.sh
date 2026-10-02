#!/usr/bin/env bash
# Rolling FULL memory dumps, start to finish (runs on the RUNNER, backgrounded).
#
# Every CYCLE_SECS seconds: dump EVERY readable region of the game process into
# /tmp/kgs/full/snap_<ts>/ (full.bin + index.txt + maps.txt), exactly like
# gen_full.sh. Keeps the newest KEEP snapshots, deletes older ones so disk and
# the final artifact stay bounded. Nothing is ever silently skipped: regions
# that fail to read are recorded in errors.txt with their rc.
#
# Resident memory is state, not events: a snapshot every few minutes misses
# nothing persistent. Transient request buffers between snapshots are covered
# by the anchor watcher (cont_cap.sh) running alongside.
set -uo pipefail
WBASE=/tmp/kgs/full
mkdir -p "$WBASE"
A="adb -s 127.0.0.1:5555"
CYCLE_SECS=${CYCLE_SECS:-300}
KEEP=${KEEP:-3}
N=${1:-24}
LOG="$WBASE/snaps.log"
echo "snaploop start N=$N every=${CYCLE_SECS}s keep=$KEEP $(date -u +%FT%TZ)" >> "$LOG"

snap_once() {
  local ts snap PID
  ts=$(date +%s)
  snap="$WBASE/snap_$ts"
  mkdir -p "$snap"
  PID=$($A shell pidof jp.konami.pesam 2>/dev/null | tr -d '\r' | awk '{print $1}')
  if [ -z "${PID:-}" ]; then echo "$ts no-pid" >> "$LOG"; rmdir "$snap" 2>/dev/null; return 1; fi
  $A shell su 0 cat /proc/$PID/maps > "$snap/maps.txt" 2>/dev/null
  local D="$snap/dump.sh"
  {
    echo 'DW=/data/local/tmp/snap; mkdir -p $DW; : > $DW/index.txt; : > $DW/errors.txt; : > $DW/full.bin'
    echo "PID=$PID"
  } > "$D"
  local page=0 n=0 skipped=0
  while read -r range perms rest; do
    [ -n "${range:-}" ] || continue
    case "$range" in *-*) ;; *) continue ;; esac
    case "${perms:-}" in r*) ;; *) continue ;; esac
    local name="$rest"
    case "$name" in
      /dev/*|*\[vvar\]*|*\[vsyscall\]*|*vdso*|*anon_inode:*) skipped=$((skipped+1)); continue ;;
    esac
    local start="${range%-*}" end="${range#*-}"
    local size=$(( 0x$end - 0x$start ))
    [ "$size" -gt 0 ] || continue
    local skip=$(( 0x$start / 4096 )) count=$(( size / 4096 ))
    [ "$count" -gt 0 ] || continue
    local esc
    esc=$(printf '%s' "$name" | tr ' ' '_' | cut -c1-60)
    [ -z "$esc" ] && esc="anon"
    printf 'dd if=/proc/%s/mem of=$DW/full.bin bs=4096 skip=%s count=%s seek=%s conv=notrunc 2>$DW/e; rc=$?; echo "%s %s %s $((%s*4096)) %s" >> $DW/index.txt; [ $rc -ne 0 ] && echo "%s rc=$rc $(head -1 $DW/e)" >> $DW/errors.txt\n' \
      "$PID" "$skip" "$count" "$page" "$range" "$perms" "$esc" "$page" "$page" "$range" >> "$D"
    page=$(( page + count ))
    n=$(( n + 1 ))
  done < "$snap/maps.txt"
  $A push "$D" /data/local/tmp/snap_dump.sh >/dev/null 2>&1
  $A shell su 0 sh /data/local/tmp/snap_dump.sh >/dev/null 2>&1
  $A pull /data/local/tmp/snap/full.bin "$snap/full.bin" >/dev/null 2>&1
  $A pull /data/local/tmp/snap/index.txt "$snap/index.txt" >/dev/null 2>&1
  $A pull /data/local/tmp/snap/errors.txt "$snap/errors.txt" >/dev/null 2>&1
  local bytes=0
  bytes=$(stat -c %s "$snap/full.bin" 2>/dev/null || echo 0)
  echo "$ts pid=$PID regions=$n skipped=$skipped MB=$(( page * 4096 / 1048576 )) pulled=$bytes" >> "$LOG"
  # prune to newest KEEP
  ls -1d "$WBASE"/snap_* 2>/dev/null | sort | head -n -"$KEEP" | while read -r old; do
    rm -rf "$old"; echo "$ts pruned $(basename "$old")" >> "$LOG"
  done
  return 0
}

for ((i = 1; i <= N; i++)); do
  snap_once || true
  sleep "$CYCLE_SECS"
done
echo "snaploop end $(date -u +%FT%TZ)" >> "$LOG"