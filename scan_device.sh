#!/system/bin/sh
# Device-side memory scan, v2.
#
# v1 reported "dumped 536870912 bytes" for EVERY region regardless of its real
# size. Cause: r.bin was never removed between iterations, so when dd failed or
# wrote nothing the previous region's file was still there and `wc -c` measured
# that. The libUE4.so dumps therefore never happened, and sign=0/header=0 for
# those regions was meaningless -- it was grepping a stale copy.
#
# Fixes here:
#   * rm -f the dump file before every dd
#   * compare dumped bytes against the expected size and SAY SO on mismatch
#   * prefer native regions (.so, anon near the .so) over the dalvik Java heap,
#     which is 512 MB of the wrong kind of memory for a native cipher key
#   * report dd's exit status
W=/data/local/tmp
mkdir -p "$W"
PID=$(pidof jp.konami.pesam | awk '{print $1}')
echo "pid=$PID"
cat /proc/$PID/maps > "$W/maps.txt"
echo "map_lines=$(wc -l < "$W/maps.txt")"

: > "$W/regions.txt"
while read -r range perms rest; do
  case "$range" in *-*) ;; *) continue ;; esac
  case "$perms" in r*) ;; *) continue ;; esac
  name=$(echo "$rest" | sed -E 's/^.*  //')
  size=$(( 0x${range#*-} - 0x${range%%-*} ))
  [ "$size" -gt 0 ] || continue
  # prio 0 = the game's own code and native heaps; prio 2 = the Java heap.
  prio=2
  case "$name" in
    *libUE4.so*) prio=0 ;;
    *.so*)        prio=1 ;;
    *heap*|*anon*) prio=1 ;;
  esac
  printf '%d %d %s %s\n' "$prio" "$size" "$range" "$name"
done < "$W/maps.txt" | sort -k1,1n -k2,2nr | head -10 | cut -d' ' -f2- > "$W/regions.txt"

echo "candidate_regions=$(grep -c . "$W/regions.txt")"
cat "$W/regions.txt"

SIGN=bTf0PnCf0wICPjEPX+PRyIPBaUpkwx5L8oa4+zxOq0VfuvYY3xVYAg==
TOTAL=0
GOOD=0
BAD=0
while read -r size range name; do
  start=${range%-*}
  np=$(( (0x${range#*-} - 0x$start) / 4096 ))
  want=$(( np * 4096 ))
  rm -f "$W/r.bin"
  dd if=/proc/$PID/mem of="$W/r.bin" bs=4096 skip=$((0x$start/4096)) count=$np 2>"$W/dd.err"
  rc=$?
  got=$(wc -c < "$W/r.bin" 2>/dev/null || echo 0)
  printf '== %s want=%s got=%s rc=%s %s\n' "$range" "$want" "$got" "$rc" "$name"
  if [ "$got" -ne "$want" ] || [ "$rc" -ne 0 ]; then
    echo "   DUMP FAILED: $(head -1 "$W/dd.err" 2>/dev/null)"
    BAD=$((BAD+1))
    continue
  fi
  GOOD=$((GOOD+1))
  S=$(grep -abo -m 10 -F "$SIGN" "$W/r.bin" | wc -l)
  H=$(grep -abo -m 10 -F pes-custom-encrypt "$W/r.bin" | wc -l)
  echo "   sign=$S header=$H"
  TOTAL=$((TOTAL+S+H))
done < "$W/regions.txt"
echo "GOOD_DUMPS=$GOOD FAILED_DUMPS=$BAD TOTAL_HITS=$TOTAL"