#!/usr/bin/env bash
# Pull every gzipped gate request body straight out of the game's heap.
#
# Why this works at all
# ---------------------
# The app's own memory states the pipeline, and this script exploits the order:
#
#     SendRequest(uri, useGzip, cookie, data, isPost)
#       useGzip = true
#       setRequestProperty pes-custom-encrypt:AES256
#
# so the body is form-urlencoded, then GZIPPED, then AES-256 encrypted. Gzip
# runs first, therefore a complete plaintext body exists in the ART heap as a
# live gzip stream, and it is findable by its two-byte magic `1f 8b`. No key, no
# injector, no TLS.
#
# Why not frida
# -------------
# frida-server cannot inject into this redroid image. Reproduced on 17.19.0 and
# 16.7.19, both "Aborted (core dumped)" at the injection step, on spawn and on
# attach. The APK is android:debuggable so JDWP is available as an alternative,
# but this route needs nothing installed in the app at all, which is why it is
# the one to run first.
#
# Why it is fast
# --------------
# The ART main space is 512 MB. Pulling that over adb and scanning it on the
# host is slow, which is exactly how the first attempt died: the run's own 150
# minute timeout killed it mid-scan and the regions went with the VM. So the
# scan happens ON THE DEVICE with grep, which is C and takes seconds, and only
# the few kilobytes around each hit are ever transferred.
#
# Usage:  bash grab_gate_plaintext.sh [adb-serial] [--region NAME]
set -uo pipefail

S="${1:-127.0.0.1:5555}"
PKG=jp.konami.pesam
OUT=/tmp/kgs
WORK=/data/local/tmp/heapdump
REPORT=$OUT/gate-plaintext.txt
LIMIT=${HIT_LIMIT:-400}
SPAN=8192

mkdir -p "$OUT"
: > "$REPORT"
say() { echo "grab: $*"; echo "grab: $*" >> "$REPORT"; }

A() { adb -s "$S" "$@"; }
AS() { A shell "$@" 2>/dev/null | tr -d '\r'; }
SU() { A shell su 0 "$@" 2>/dev/null | tr -d '\r'; }

pid=$(AS pidof "$PKG" | tr -d '\r' | awk '{print $1}')
[ -n "$pid" ] || { say "package is not running"; exit 1; }
say "pid $pid"

SU mkdir -p "$WORK" || { say "cannot make $WORK as root"; exit 1; }
# The redirect on the dd below (2>"$WORK/dd.err") is performed by THIS shell,
# which is not root. If root created $WORK with default 0755 the unprivileged
# shell cannot create files in it, and the dump silently produced nothing:
#   line 154: /data/local/tmp/heapdump/dd.err: No such file or directory
#   grab: region 1 unreadable:
# Make it world-writable so the redirect works.
SU chmod 777 "$WORK" || say "warn: could not chmod $WORK"

# Largest writable anonymous regions: where a Java heap and a native heap both
# live. The named dalvik-main space is the one that held the request strings.
maps=$(SU cat "/proc/$pid/maps")
say "map lines: $(printf '%s\n' "$maps" | wc -l)"

# Region selection. The previous version kept only writable anonymous regions
# >= 64 MB and took the top 6. On the 2026-10-01 run that selected ZERO regions
# ("candidate regions:" printed nothing), so the scan never ran and the reported
# "0 gzip-magic offsets" meant nothing was inspected -- not that nothing was there.
#
# An AES key is not going to live in one large anonymous blob. It sits in a small
# structure, or in a loaded object's data segment. So: take every readable
# region, weight the ones named after a .so or the heap, and let MAXREGIONS cap
# the work.
MAXREGIONS=${MAXREGIONS:-40}
MAXBYTES=${MAXBYTES:-2147483648}     # 2 GB ceiling on what we pull

# Feed the selection loop from a FILE, not a here-string. With a here-string plus
# another `while read` in the same script, the producer consumed exactly ONE line
# and exited (confirmed with `bash -x`) -- which is how this scan previously
# reported "0 offsets" having inspected nothing at all. Adding any second bare
# `while read` over stdin here reintroduces it, so every loop in this script
# reads from an explicit redirect.
printf '%s\n' "$maps" > "$OUT/maps.txt"

: > "$OUT/regions.txt"
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
  start_hex="${range%-*}"
  end_hex="${range#*-}"
  size=$(( 0x$end_hex - 0x$start_hex ))
  [ "$size" -gt 0 ] || continue
  # Escaped separators: a bare word in a case pattern list ends the list early,
  # which made `continue` fire for every region regardless of its name.
  case "$name" in
    /dev/* | \[vvar\] | \[vsyscall\] | anon_inode:*) continue ;;
  esac
  # Priority: 0 = named .so data or heap (most likely), 1 = other anon.
  prio=1
  case "$name" in
    *.so* | *lib* | *heap* | *dalvik* | *art* | *jit*) prio=0 ;;
    "" | *" "* | *anon*)                              prio=1 ;;
    *) prio=0 ;;
  esac

  printf '%d %d %s %s\n' "$prio" "$size" "$range" "$name"
done < "$OUT/maps.txt" | sort -k1,1n -k2,2nr | head -"$MAXREGIONS" \
  | cut -d' ' -f2- > "$OUT/regions.txt"

say "candidate regions: $(wc -l < "$OUT/regions.txt")"
while read -r size range _ name; do
  say "  $range  $((size / 1048576)) MB  ${name:-anon}"
done < "$OUT/regions.txt"

if [ ! -s "$OUT/regions.txt" ]; then
  say "FATAL: no readable regions matched. Aborting rather than reporting a false 0."
  exit 2
fi

total_hits=0
index=0

# Search needles, in order of usefulness.
#
# 1. The `sign` cookie value, verbatim. Every gate request carries
#    Cookie: sign=<40 bytes base64>. That exact byte string must be in memory
#    (request headers, the curl handle, the builder's buffer). The AES key is
#    referenced by the same code path, so it is likely nearby -- which makes
#    this the most useful anchor for finding it.
# 2. The literal "pes-custom-encrypt", the header name the game writes. That
#    string is adjacent to the code that selects the cipher.
# 3. gzip magic 1f 8b -- the pre-encryption body, kept because it is cheap and
#    because recovering one plaintext body would validate the whole model.
#
# Set SIGN_B64 to the captured sign value to enable anchor 1.
# No default value on purpose: this token is a LIVE gate session cookie and the
# repo is public. Supply it at run time from the runner's secrets:
#   SIGN_B64=$(cat "$W/creds/sign_b64")
# Or read a fresh one straight out of a capture (grep -m1 -o 'sign=[A-Za-z0-9+/=]\{40,\}' flows.mitm | cut -d= -f2-).
: "${SIGN_B64:?set SIGN_B64 (see comment above) - it is a live session cookie, not a constant}"

while read -r size range _name; do
  index=$((index + 1))
  start="${range%-*}"
  end="${range#*-}"
  npages=$(( (0x$end - 0x$start) / 4096 ))
  [ "$npages" -gt 0 ] || continue
  bin="$WORK/region$index.bin"

  say "dumping region $index $range ($((size / 1048576)) MB) to device"
  SU dd if="/proc/$pid/mem" of="$bin" bs=4096 skip=$((0x$start / 4096)) \
     count="$npages" 2>"$WORK/dd.err" >/dev/null
  if [ ! -s "$bin" ]; then
    say "  region $index unreadable: $(SU cat "$WORK/dd.err" | head -1)"
    continue
  fi

  # Record what is actually in this region, so a 0-hit region is provably
  # inspected rather than merely reported.
  say "  region $index dumped $(SU wc -c < "$bin") bytes"

  # On-device grep is C and fast; this is what keeps the whole thing inside one
  # run. Anchors are searched one at a time so we can attribute hits.
  for anchor in sign magic header gzip; do
    # Every anchor is searched as a FIXED string (-F). The gzip magic is passed
    # as the two-character escape so no shell quoting hazard exists: "\x1f" in
    # the C locale is the literal 4-character string, which grep -F would not
    # match, so for that one anchor only we use a regex pattern instead.
    case "$anchor" in
      sign)   offsets=$(SU grep -abo -m "$LIMIT" -F "$SIGN_B64" "$bin") ;;
      header) offsets=$(SU grep -abo -m "$LIMIT" -F "pes-custom-encrypt" "$bin") ;;
      magic)  offsets=$(SU grep -abo -m "$LIMIT" -P "\x1f\x8b" "$bin" 2>/dev/null) \
              || offsets=$(SU grep -abo -m "$LIMIT" -F "$(printf '\037\213')" "$bin") ;;
      *)      offsets="" ;;
    esac

    n=$(printf '%s' "$offsets" | grep -c ':' )
    say "  region $index anchor=$anchor hits=$n"
    [ "$n" -gt 0 ] || continue

    printf '%s\n' "$offsets" | head -"$LIMIT" | while IFS=: read -r off _; do
      [ -n "$off" ] || continue
      win="$WORK/win_${index}_${anchor}_${off}.bin"
      SU dd if="$bin" of="$win" bs=1 skip="$off" count="$SPAN" 2>/dev/null >/dev/null
      # Unique destination per hit -- the old code reused one filename and
      # silently kept only the last window.
      A pull "$win" "$OUT/win_${index}_${anchor}_${off}.bin" >/dev/null 2>&1
    done
    total_hits=$((total_hits + n))
  done

  SU rm -f "$bin" 2>/dev/null   # free space; keep only the small windows
done < "$OUT/regions.txt"

say "TOTAL ANCHOR HITS: $total_hits"
say "windows kept in $OUT (win_*.bin)"

# The per-window gzip decoder that used to live here was removed: the old
# version pulled every window to the same path ("$OUT/win.bin") so only the
# last hit survived. Windows are now kept individually as
# $OUT/win_<region>_<anchor>_<offset>.bin and decoded offline with
# decode_windows.py, which is faster and reproducible.

SU rm -rf "$WORK"
say "scanned regions, $total_hits anchor hits"
say "windows kept: $(ls -1 "$OUT"/win_*.bin 2>/dev/null | wc -l)"
say "report: $REPORT"
exit 0
