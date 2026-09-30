#!/usr/bin/env bash
# Dump the full view hierarchy over plain adb (no docker) and list every
# tappable node with its center. The macOS-emulator / real-device twin of
# uidump.sh.
#
# Usage:  bash uidump_mac.sh [out-xml-path]
set -uo pipefail

OUT="${1:-/tmp/kgs/ui.xml}"

adb exec-out uiautomator dump /dev/tty 2>/dev/null | sed -n '/^<?xml/,$p;/^<hierarchy/,$p' > "$OUT"
[ -s "$OUT" ] || { echo "UIDUMP-MAC: dump is EMPTY"; exit 1; }

python3 - "$OUT" <<'PY'
import re, sys, html
xml = open(sys.argv[1], encoding="utf-8", errors="replace").read()
nodes = re.findall(r'<node [^>]*>', xml)
print("UIDUMP-MAC: %d nodes" % len(nodes))
n = 0
for tag in nodes:
    def attr(name):
        m = re.search(name + r'="([^"]*)"', tag)
        return html.unescape(m.group(1)) if m else ""
    clickable = attr("clickable") == "true"
    enabled = attr("enabled") == "true"
    cls = attr("class").split(".")[-1]
    rid = attr("resource-id").split("/")[-1]
    text = (attr("text") + " " + attr("content-desc")).strip()
    b = re.search(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", attr("bounds"))
    if not b:
        continue
    x1, y1, x2, y2 = map(int, b.groups())
    if x2 <= x1 or y2 <= y1:
        continue
    mark = "CLICK" if (clickable and enabled) else "-----"
    print("  %s  (%4d,%-4d)  %-18s %-28s %s"
          % (mark, (x1 + x2) // 2, (y1 + y2) // 2, cls[:18], rid[:28],
             text[:60]))
    if clickable and enabled:
        n += 1
print("UIDUMP-MAC: %d clickable" % n)
PY
