#!/usr/bin/env bash
# Reinstall the game's staged splits through the pm session API.
#
# This is the path proven to work on this phone (adb install-multiple fails
# here; the session API succeeds, pads included). It lives in a FILE because
# the live loop evaluates operator commands with `eval` under `set -u`: any
# `$VAR` or `$(...)` in a typed command is expanded by the loop's own shell
# first, and an unbound variable kills the whole session instantly. That is
# exactly what killed the 08:46 session at 10:39 -- a reinstall one-liner with
# `$S` in it. Files don't have that problem.
#
# Usage (as a live-loop command):  exec bash kgs-login/live/pm_reinstall.sh [container]
set -uo pipefail

C="${1:-redroid}"

sudo docker exec "$C" sh -c '
  cd /data/local/tmp/splits || exit 1
  S=$(pm install-create -r 2>&1 | grep -oE "[0-9]+" | tail -1)
  echo "session=$S"
  [ -n "$S" ] || { echo "NO SESSION"; exit 1; }
  for f in ./*.apk; do
    pm install-write "$S" "$(basename "$f")" "$f" >/dev/null 2>&1 \
      || echo "FAIL $f"
  done
  pm install-commit "$S"
  echo "commit rc=$?"
'
echo "reinstall rc=$?"
pm list packages 2>/dev/null | grep -i konami || \
  sudo docker exec "$C" /system/bin/pm list packages 2>/dev/null | grep -i konami
