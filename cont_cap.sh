#!/usr/bin/env bash
# Continuous memory grabber (runs on the RUNNER, backgrounded).
# Watches the game from boot and snapshots every cycle while it lives.
# All 64-bit arithmetic happens HERE (runner bash is 64-bit); the device only
# ever receives decimal literals, because Android sh is 32-bit and overflows.
set -uo pipefail
W=/tmp/live-res/cap
mkdir -p "$W"
A="adb -s 127.0.0.1:5555"
LOG="$W/loop.log"
ANCHORS="sign= gate_CMD_ CMD_LOGIN session_id pes-custom-encrypt"
KNOWN_SIGN="bTf0PnCf0wICPjEPX+PRyIPBaUpkwx5L8oa4+zxOq0VfuvYY3xVYAg=="
N=${1:-60}
echo "loop start N=$N $(date -u +%FT%TZ)" >> "$LOG"
for ((i=1; i<=N; i++)); do
  ts=$(date +%s)
  PID=$($A shell pidof jp.konami.pesam 2>/dev/null | tr -d '\r' | awk '{print $1}')
  if [ -z "${PID:-}" ]; then echo "$ts cycle=$i no-pid" >> "$LOG"; sleep 8; continue; fi
  $A shell su 0 cat /proc/$PID/maps > "$W/maps.$ts.txt" 2>/dev/null
  # targets: libUE4 rw mapping (bss/env) + native anon heaps >=16MB, top 5
  : > "$W/t.$ts"
  while read -r range perms rest; do
    [ -n "${range:-}" ] || continue
    case "$range" in *-*) ;; *) continue ;; esac
    case "${perms:-}" in r*) ;; *) continue ;; esac
    name="$rest"
    size=$(( 0x${range#*-} - 0x${range%%-*} ))
    [ "$size" -gt 0 ] || continue
    case "$name" in *libUE4.so*)
      case "$perms" in rw*) prio=0 ;; *) prio=3 ;; esac ;;
      *scudo*|*heap*) prio=1 ;;
      *anon*) [ "$size" -ge 16777216 ] && prio=2 || continue ;;
      *) continue ;;
    esac
    printf '%d %d %s\n' "$prio" "$size" "$range"
  done < "$W/maps.$ts.txt" | sort -k1,1n -k2,2nr | head -6 | cut -d' ' -f2- > "$W/t.$ts"
  echo "$ts cycle=$i pid=$PID regions=$(grep -c . "$W/t.$ts")" >> "$LOG"
  while read -r size range; do
    start="${range%-*}"; end="${range#*-}"
    skip=$(( 0x$start / 4096 )); count=$(( (0x$end - 0x$start) / 4096 ))
    $A shell su 0 dd if=/proc/$PID/mem of=/data/local/tmp/cyc.bin bs=4096 skip=$skip count=$count 2>/dev/null >/dev/null
    got=$($A shell su 0 wc -c /data/local/tmp/cyc.bin 2>/dev/null | tr -d '\r' | awk '{print $1}')
    for an in $ANCHORS; do
      n=$($A shell su 0 grep -abo -m 6 -F "$an" /data/local/tmp/cyc.bin 2>/dev/null | tr -d '\r' | wc -l)
      [ "$n" -gt 0 ] && echo "$ts $range $an hits=$n size=$size got=$got" >> "$LOG"
    done
    n=$($A shell su 0 grep -abo -m 6 -F "$KNOWN_SIGN" /data/local/tmp/cyc.bin 2>/dev/null | tr -d '\r' | wc -l)
    [ "$n" -gt 0 ] && echo "$ts $range KNOWN_SIGN hits=$n" >> "$LOG"
  done < "$W/t.$ts"
  sleep 5
done
echo "loop end $(date -u +%FT%TZ)" >> "$LOG"