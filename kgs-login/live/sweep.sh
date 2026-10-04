#!/usr/bin/env bash
# Continuous memory sweeper: copy the game's WHOLE writable memory, cycle
# after cycle, from before launch until the process exits.
#
# Why continuous: a single copy taken at one moment came back without the
# key. The key exists only while it is in use, so a loop of full copies is
# the only way to be sure some cycle overlaps the moment it is alive. This
# script never decides anything -- it only copies. find_key.py decides later.
#
# Per cycle (same dd mechanism as scripts/dump_game_mem.py, proven on image):
#   maps -> every writable region >= MIN_REGION bytes -> page-aligned dd to a
#   device file -> pull -> scan for markers -> gzip -> delete device file.
# A cycle containing a login marker (CMD_LOGIN, /pes22/gate/, ...) is flagged
# HAS_MARKERS and kept; ordinary cycles rotate out under MAXGB.
#
# Run:  nohup bash sweep.sh > /tmp/kgs/sweep.log 2>&1 &
# Stop: touch /tmp/kgs/sweep/STOP   (or let it end when the game exits)
set -u
S=127.0.0.1:5555
PKG=jp.konami.pesam
W=${W:-/tmp/kgs}
DIR=$W/sweep
KEEP=${KEEP:-4}          # newest ordinary cycles always kept
MAXGB=${MAXGB:-6}        # total disk budget for ordinary cycles
MAXSECS=${MAXSECS:-14400}
MIN_REGION=65536
MARKERS="CMD_LOGIN CMD_GET_SESSION_ID CMD_CREATEJOIN_ROOM CMD_GET_ROOM_INFO /pes22/gate/ command_service packMode"

say() { echo "[sweep $(date -u +%H:%M:%S)] $*"; }
mkdir -p "$DIR"

A() { adb -s "$S" "$@"; }

# size in bytes of the sweep dir (du -sk is in KB)
dir_kb() { du -sk "$DIR" 2>/dev/null | cut -f1; }

prune() {
  # delete oldest ordinary cycles until under KEEP count and MAXGB
  local kb=$((MAXGB * 1024)) d n
  n=$(find "$DIR" -maxdepth 1 -type d -name 'c[0-9]*' | wc -l)
  while :; do
    [ "$n" -le "$KEEP" ] && [ "$(dir_kb)" -le "$kb" ] && break
    d=$(find "$DIR" -maxdepth 1 -type d -name 'c[0-9]*' ! -name HAS_MARKERS \
        | sort | head -1)
    [ -z "$d" ] && break
    rm -rf "$d"
    n=$((n - 1))
    say "pruned $(basename "$d") (over count or ${MAXGB}GB cap)"
  done
}

start=$(date +%s)
cycle=0
pid=""
last_pid=""
say "armed: waiting for $PKG (max ${MAXSECS}s)"

while :; do
  [ -f "$DIR/STOP" ] && { say "STOP file present, ending"; break; }
  [ $(( $(date +%s) - start )) -gt "$MAXSECS" ] && { say "max time reached"; break; }

  pid=$(A shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
  if [ -z "$pid" ]; then
    if [ -n "$last_pid" ]; then
      say "game exited (was pid $last_pid), one final pass done or not -- ending"
      break
    fi
    sleep 2
    continue
  fi
  if [ "$pid" != "$last_pid" ]; then
    say "game pid $pid -- starting capture"
    last_pid=$pid
    cycle=0
  fi

  cycle=$((cycle + 1))
  cdir=$(printf '%s/c%04d' "$DIR" "$cycle")
  mkdir -p "$cdir"
  t0=$(date +%s)
  bytes=0
  regions=0
  hits=""

  A shell su 0 cat /proc/$pid/maps > "$cdir/maps" 2>/dev/null
  tr -d '\r' < "$cdir/maps" > "$cdir/maps.lf" && mv "$cdir/maps.lf" "$cdir/maps"

  while read -r range perms _rest; do
    case "$perms" in *w*) ;; *) continue ;; esac
    hex_s=${range%-*}; hex_e=${range#*-}
    s=$((0x$hex_s)); e=$((0x$hex_e))
    sz=$((e - s))
    [ "$sz" -ge "$MIN_REGION" ] || continue
    skip=$((s / 4096)); count=$((sz / 4096))
    rfile=$(printf '%s/r_%012x.bin' "$cdir" "$s")
    A shell su 0 sh -c "dd if=/proc/$pid/mem of=/data/local/tmp/sw.bin bs=4096 skip=$skip count=$count 2>/data/local/tmp/sw.err"
    if ! A pull /data/local/tmp/sw.bin "$rfile" >/dev/null 2>&1; then
      say "  PULL FAILED region 0x$hex_s"
      rm -f "$rfile"
      continue
    fi
    rm -f /data/local/tmp/sw.bin
    got=$(wc -c < "$rfile" 2>/dev/null | tr -d ' \r')
    if [ "${got:-0}" -lt "$count" ]; then
      # partial read is kept and logged; a gap must be visible, never silent
      echo "$hex_s wanted=$((count * 4096)) got=${got:-0}" >> "$cdir/truncated.log"
    fi
    bytes=$((bytes + ${got:-0}))
    regions=$((regions + 1))
    for m in $MARKERS; do
      if grep -aqF -- "$m" "$rfile" 2>/dev/null; then
        hits="$hits $m"
        touch "$cdir/HAS_MARKERS"
      fi
    done
    gzip -1 -f "$rfile" 2>/dev/null
  done < "$cdir/maps"

  say "cycle $cycle: $regions regions $bytes bytes $(( $(date +%s) - t0 ))s markers:${hits:- none}"
  [ -e "$cdir/HAS_MARKERS" ] && say "  cycle $cycle FLAGGED (login material present), kept"
  prune
done

rm -f /data/local/tmp/sw.bin /data/local/tmp/sw.err 2>/dev/null
say "sweeper ended: $cycle cycles, $(dir_kb) KB on disk"
exit 0
