#!/usr/bin/env bash
# Walk eFootball through onboarding to the main menu, capturing every step.
#
# Why this exists
# ---------------
# The chain below was established by hand on 2026-10-01 and is recorded here so
# it does not have to be rediscovered by tapping into the dark. Two hard-won
# facts are baked in:
#
#   1. This game IGNORES a zero-duration tap. Every press is
#      `input swipe X Y X Y 250` -- a 250 ms hold. A bare `input tap` at the
#      correct coordinates does nothing at all, which is indistinguishable from
#      having the wrong coordinates, and cost a long stretch of one session
#      before the difference was spotted. Only the hold works.
#
#   2. Play Asset Delivery is mandatory. Without it the title screen never
#      offers a way online, so there is no Konami login and no room creation.
#
# Every press is followed by a screenshot, and the script stops on the first
# step that does not change the screen, rather than carrying on regardless.
# That is the difference between this and a blind chain: if the game shows an
# unexpected dialog, the run stops and a human looks, instead of the script
# tapping confidently through something it does not understand.
#
# Usage:  bash onboard.sh [adb-serial] [--from N]
#         --from N   resume at step N, for picking up after a stop
set -uo pipefail

S="${1:-127.0.0.1:5555}"
A="adb -s $S"
PKG=jp.konami.pesam
OUT=/tmp/live-res/onboard
FROM=1
[ "${2:-}" = "--from" ] && FROM="${3:-1}"

mkdir -p "$OUT"
say() { echo "onboard: $*"; }

# A 250 ms hold. Never `input tap` -- see note 1 above.
hold() { $A shell input swipe "$1" "$2" "$1" "$2" 250 >/dev/null 2>&1; }
shot() { $A exec-out screencap -p > "$OUT/$1.png" 2>/dev/null; }
size() { wc -c < "$OUT/$1.png" 2>/dev/null | tr -d ' '; }
wait_s() { sleep "$1"; }

step=0
# Each step: label, x, y, settle seconds, and the screenshot name to compare
# against the previous one. A step that changes nothing is a stop condition.
run_step() {
  local label="$1" x="$2" y="$3" settle="$4" name="$5"
  step=$((step + 1))
  [ "$step" -lt "$FROM" ] && return 0
  local before after
  before=$(size prev)
  say "step $step: $label  ($x,$y)"
  hold "$x" "$y"
  wait_s "$settle"
  shot "$name"
  after=$(size "$name")
  if [ -n "$before" ] && [ "$before" = "$after" ] && [ "$before" != "0" ]; then
    say "STOP: screen did not change (${after} bytes, same as before)."
    say "This is the expected symptom of a wrong coordinate or an"
    say "unexpected dialog. Look at $OUT/$name.png before going further."
    cp -f "$OUT/$name.png" /tmp/live-res/screen.png 2>/dev/null
    exit 3
  fi
  cp -f "$OUT/$name.png" /tmp/live-res/screen.png 2>/dev/null
  cp -f "$OUT/$name.png" "$OUT/prev.png" 2>/dev/null
  say "  ok, screen is ${after} bytes"
}

say "device: $($A shell getprop ro.product.model 2>/dev/null | tr -d '\r')"

if [ "$FROM" -le 1 ]; then
  say "launching the game; the splash takes a while under software rendering"
  $A shell am force-stop "$PKG" >/dev/null 2>&1
  wait_s 4
  $A shell am start -n "$PKG/com.epicgames.ue4.SplashActivity" >/dev/null 2>&1
  wait_s 90
  shot 00-launched
  cp -f "$OUT/00-launched.png" "$OUT/prev.png" 2>/dev/null
  say "  launched"
fi

# "Viewing full screen" system dialog, then the language list.
run_step "dismiss fullscreen dialog" 853 403 9  01-fullscreen
run_step "language: Done"            1139 677 15 02-language

# Country / Region, with its cannot-change-later confirmation.
run_step "country: Next"              1139 677 15 03-country-next
run_step "country: Confirm"           807 460 15 04-country-confirm

# Birth Year and Month. The picker defaults to January 2000, which is a valid
# adult age, so there is no need to touch the spinners.
run_step "birth: open picker"        1206 343 13 05-birth-open
run_step "birth: picker Done"         640 640 13 06-birth-done
run_step "birth: Next"               1139 677 15 07-birth-next
run_step "birth: Confirm"             807 478 15 08-birth-confirm

# Terms of Use needs the checkbox ticked before Consent becomes active.
run_step "terms: tick consent box"     146 534 9  09-terms-tick
run_step "terms: Consent"              899 640 15 10-terms-consent

# Privacy Notice, then three survey questions.
run_step "privacy: Consent"            899 640 15 11-privacy
run_step "survey 1: pick an option"    400 349 9  12-survey1-pick
run_step "survey 1: Continue"          640 640 14 13-survey1-next
run_step "survey 2: pick an option"    400 267 9  14-survey2-pick
run_step "survey 2: Continue"          640 640 14 15-survey2-next
run_step "survey 3: pick an option"    400 267 9  16-survey3-pick
run_step "survey 3: Continue"          640 640 14 17-survey3-next

# Title screen. This is the gate: without it there are no online features, and
# therefore no Konami login and no room creation.
run_step "title: open data prompt"    1206 662 12 18-title
run_step "title: Download 59.76 MB"    807 478 30 19-title-download

say "onboarding sequence finished; screenshots in $OUT"
say "next step is the main menu, then the hamburger at (1207, 661)"
exit 0
