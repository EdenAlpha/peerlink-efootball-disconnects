#!/usr/bin/env bash
# Tap a UI element by its visible text, over plain adb (no docker).
# For the macOS emulator run: the only device on adb is the phone.
#
# Usage:  bash uitap_mac.sh <text-regex>
# Prints TAP x y <text> on success. Exits 1 LOUDLY on miss.
set -uo pipefail

PAT="${1:?pattern required}"

XML=$(adb exec-out uiautomator dump /dev/tty 2>/dev/null | sed -n '/^<?xml/,$p;/^<hierarchy/,$p')
if [ -z "$XML" ]; then
  echo "UITAP-MAC: dump empty"
  exit 1
fi
MATCH=$(echo "$XML" | python3 -c "
import sys, re, html
xml = sys.stdin.read()
pat = re.compile(sys.argv[1])
best = None
for m in re.finditer(r'<node [^>]*>', xml):
    tag = m.group(0)
    def attr(n):
        mm = re.search(n + r'=\"([^\"]*)\"', tag)
        return html.unescape(mm.group(1)) if mm else ''
    text = (attr('text') + ' ' + attr('content-desc')).strip()
    if text and pat.search(text):
        b = re.search(r'bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]', tag)
        if b:
            x1, y1, x2, y2 = map(int, b.groups())
            if x2 > x1 and y2 > y1:
                best = ((x1 + x2) // 2, (y1 + y2) // 2, text)
                break
if best:
    print('%d %d %s' % best)
" "$PAT")

if [ -z "$MATCH" ]; then
  echo "UITAP-MAC: no match for [$PAT]"
  exit 1
fi
X=$(echo "$MATCH" | awk '{print $1}')
Y=$(echo "$MATCH" | awk '{print $2}')
TEXT=$(echo "$MATCH" | cut -d' ' -f3-)
adb shell input tap "$X" "$Y" >/dev/null 2>&1
echo "UITAP-MAC: tapped ($X,$Y) [$TEXT]"
