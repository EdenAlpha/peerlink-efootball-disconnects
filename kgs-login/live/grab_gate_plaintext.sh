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

# Largest writable anonymous regions: where a Java heap and a native heap both
# live. The named dalvik-main space is the one that held the request strings.
maps=$(SU cat "/proc/$pid/maps")
say "map lines: $(printf '%s\n' "$maps" | wc -l)"

region_list=""
printf '%s\n' "$maps" | while read -r range _ rest; do
  case "$range" in
    *-*) ;;
    *) continue ;;
  esac
  case "$rest" in
    *rw*) ;;
    *) continue ;;
  esac
  name="${rest##*  }"
  size=$(( 0x${range#*-} - 0x${range%%-*} ))
  [ "$size" -ge 67108864 ] || continue
  printf '%s %s\n' "$size" "$range"
done | sort -rn | head -6 > "$OUT/regions.txt"

say "candidate regions:"
while read -r size range; do
  say "  $range  $((size / 1048576)) MB"
done < "$OUT/regions.txt"

total_hits=0
index=0

while read -r size range; do
  index=$((index + 1))
  start="${range%-*}"
  end="${range#*-}"
  npages=$(( (0x$end - 0x$start) / 4096 ))
  bin="$WORK/region$index.bin"

  say "dumping region $index $range ($((size / 1048576)) MB) to device"
  SU dd if="/proc/$pid/mem" of="$bin" bs=4096 skip=$((0x$start / 4096)) \
     count="$npages" 2>"$WORK/dd.err" >/dev/null
  if [ ! -s "$bin" ]; then
    say "  region $index unreadable: $(SU cat "$WORK/dd.err" | head -1)"
    continue
  fi

  # grep for the gzip magic on the device: this is the fast part, and it is why
  # the whole thing fits in a run that also has to install 2 GB and onboard.
  offsets=$(SU grep -abo -m "$LIMIT" $'\x1f\x8b' "$bin")
  n=$(printf '%s' "$offsets" | grep -c ':' )
  say "  region $index has $n gzip-magic offsets"

  printf '%s\n' "$offsets" | head -"$LIMIT" | while IFS=: read -r off _; do
    [ -n "$off" ] || continue
    win="$WORK/win_${index}_${off}.bin"
    SU dd if="$bin" of="$win" bs=1 skip="$off" count="$SPAN" 2>/dev/null >/dev/null
    A pull "$win" "$OUT/win.bin" >/dev/null 2>&1
    [ -s "$OUT/win.bin" ] || continue
    if python3 - "$OUT/win.bin" <<'PY' >> "$REPORT" 2>/dev/null
import gzip, io, re, sys
blob = open(sys.argv[1], "rb").read()
i = 0
while True:
    i = blob.find(b"\x1f\x8b", i)
    if i < 0:
        break
    for end in (len(blob), min(len(blob), i + 8192)):
        try:
            data = gzip.GzipFile(fileobj=io.BytesIO(blob[i:end])).read()
        except Exception:
            continue
        if not data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            break
        if "=" in text and re.search(r"(uid|opt|libVer|token|cmd|device|lang|auth)", text, re.I):
            print("  ---- REQUEST BODY (%d bytes) ----" % len(data))
            print("  " + text[:900].replace("\n", "\n  "))
        break
    i += 1
PY
    then :; fi
    SU rm -f "$win"
  done
  total_hits=$((total_hits + n))
  SU rm -f "$bin"
done < "$OUT/regions.txt"

SU rm -rf "$WORK"
say "scanned regions, $total_hits gzip-magic offsets seen"
say "report: $REPORT"
grep -c 'REQUEST BODY' "$REPORT" 2>/dev/null | sed 's/^/request bodies recovered: /' >> "$REPORT"
exit 0
