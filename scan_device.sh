#!/system/bin/sh
# Device-side memory scan, v3.
#
# All dd arguments are DECIMAL literals computed by dd_args.sh on the runner,
# because Android's shell does $(( )) in 32 bits and overflows a 52-bit address
# into a negative count ("dd: -59839 < 0"). The device performs no arithmetic.
W=/data/local/tmp
mkdir -p "$W"
PID=$(pidof jp.konami.pesam | awk '{print $1}')
echo "pid=$PID"

SIGN=bTf0PnCf0wICPjEPX+PRyIPBaUpkwx5L8oa4+zxOq0VfuvYY3xVYAg==
TOTAL=0
GOOD=0
BAD=0

scan() {
  skip=$1
  count=$2
  label=$3
  want=$(( count * 4096 ))
  rm -f "$W/r.bin"
  dd if=/proc/$PID/mem of="$W/r.bin" bs=4096 skip="$skip" count="$count" 2>"$W/dd.err"
  rc=$?
  got=$(wc -c < "$W/r.bin" 2>/dev/null || echo 0)
  echo "== $label skip=$skip pages=$count want=$want got=$got rc=$rc"
  if [ "$got" -ne "$want" ] || [ "$rc" -ne 0 ]; then
    echo "   FAILED: $(head -1 "$W/dd.err" 2>/dev/null)"
    BAD=$((BAD+1))
    return
  fi
  GOOD=$((GOOD+1))
  S=$(grep -abo -m 10 -F "$SIGN" "$W/r.bin" | wc -l)
  H=$(grep -abo -m 10 -F pes-custom-encrypt "$W/r.bin" | wc -l)
  G=$(grep -abo -m 10 -F "AES256" "$W/r.bin" | wc -l)
  echo "   sign=$S header=$H AES256=$G"
  TOTAL=$((TOTAL+S+H))
}

scan 66215417409 25417 "libUE4.so r-xp 99MB"
scan 66215407128 10278 "libUE4.so rw-p 40MB"
scan 66215442829  3470 "libUE4.so 14MB"
scan 66215446302   101 "libUE4.so 413KB"
scan 66214839806 58881 "scudo 230MB"
scan 66215218736 18383 "scudo 72MB"

echo "GOOD_DUMPS=$GOOD FAILED_DUMPS=$BAD TOTAL_HITS=$TOTAL"