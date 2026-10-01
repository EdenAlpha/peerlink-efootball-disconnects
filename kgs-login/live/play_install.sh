#!/usr/bin/env bash
# Get the game installed BY PLAY, and wait for Play Asset Delivery to finish.
#
# This is the run of 2026-09-30 turned into a script. That run worked and it
# was never written down anywhere except the git history of the live command
# branch, which is why it had to be rediscovered from scratch on 2026-10-01.
# The steps, and why each one exists:
#
#   1. Uninstall the sideloaded copy. Play Asset Delivery only serves asset
#      packs to an app PLAY ITSELF installed. A `pm install-create` sideload
#      installs the binary and nothing else, and the game then boots and
#      reports "Download Failed 0%" -- which is exactly what the 2026-10-01
#      run did. live-cmd commit UI, 23:42, was the uninstall.
#
#   2. No interception on this path. Play will not download through a proxy
#      whose certificate it rejects. Measured on 2026-10-01 at 06:01 as
#      "Client TLS handshake failed ... play.googleapis.com". The proxy is
#      armed in a later step, after the assets are on disk.
#
#   3. Install from the Play page (live-cmd UI -> UJ, tap 360 780), skip the
#      payment gate (UK/UL), then wait for the packs (UM/UV).
#
# Coordinates are from the 720x1280 screenshots of that run and were read off
# the real screen.
#
# Usage:  bash play_install.sh [adb-serial]
# Env:    PEERLINK_GMAIL PEERLINK_GPASS  (from Actions secrets)
#         PEERLINK_GCODE                 optional rolling 2FA code; when absent
#                                       the script stops and says so rather
#                                       than typing a wrong one.
# Exit:   0 assets are on disk and the app is installed
#         2 a human is required (no 2FA code available)
#         1 something else went wrong; the last screenshot is kept
set -uo pipefail

S="${1:-127.0.0.1:5555}"
A="adb -s $S"
PKG=jp.konami.pesam
SHOT_DIR=/tmp/live-res/install
W=/tmp/kgs
mkdir -p "$SHOT_DIR" "$W/creds"
chmod 700 "$W/creds" 2>/dev/null

say() { echo "install: $*"; }
shot() { $A exec-out screencap -p > "$SHOT_DIR/$1.png" 2>/dev/null; }
tap()  { $A shell input tap "$1" "$2" >/dev/null 2>&1; sleep "${3:-6}"; }
key()  { $A shell input keyevent "$1" >/dev/null 2>&1; sleep "${2:-3}"; }
text() { $A shell input text "$1" >/dev/null 2>&1; sleep 2; }
have() { $A shell "$@" 2>/dev/null | tr -d '\r'; }

LAST_MB=""
# Publish progress to live-res. Without this the whole of step 04b is
# invisible: run logs are unreadable while the job runs, and the live control
# loop does not open until step 05 -- so sign-in and the ~45 minute asset
# download would be a three-hour silence. See publish.sh.
pub() {
  local label="$1" shot=""
  [ -n "${2:-}" ] && [ -s "$SHOT_DIR/$2.png" ] && shot="$SHOT_DIR/$2.png"
  {
    echo "stage=play_install"
    echo "label=$label"
    echo "time=$(date -u +%H:%M:%S)"
    echo "mb=${LAST_MB:-?}"
  } > /tmp/live-res/status.txt 2>/dev/null
  bash kgs-login/live/publish.sh "$label" "$shot" >/dev/null 2>&1 || true
}

GMAIL="${PEERLINK_GMAIL:-}"
GPASS="${PEERLINK_GPASS:-}"
GCODE="${PEERLINK_GCODE:-}"
[ -z "$GPASS" ] && [ -f "$W/creds/GPASS" ] && GPASS=$(cat "$W/creds/GPASS")
[ -z "$GMAIL" ] && [ -f "$W/creds/GMAIL" ] && GMAIL=$(cat "$W/creds/GMAIL")
[ -z "$GCODE" ] && [ -f "$W/creds/GCODE" ] && GCODE=$(cat "$W/creds/GCODE")

# ---------------------------------------------------------------- sign-in ---
# "add account" rows in the account manager all say the same address, so the
# signed-in state is read from the account list rather than guessed.
signed_in() { have dumpsys account 2>/dev/null | grep -q "type=com.google"; }

sign_in() {
  if signed_in; then say "account already present, skipping sign-in"; return 0; fi
  [ -n "$GMAIL" ] && [ -n "$GPASS" ] || { say "NO CREDENTIALS AVAILABLE"; return 1; }

  say "opening the Play Store"
  $A shell am force-stop com.android.vending >/dev/null 2>&1
  $A shell am start -n com.android.vending/com.google.android.finsky.activities.MainActivity \
    >/dev/null 2>&1
  sleep 14
  shot store-open
  pub "play store open" store-open
  tap 360 907 14        # Sign in
  shot signin-landed
  pub "after sign-in tap" signin-landed

  # The email field, then the password field. Coordinates are position- and
  # screen-dependent, so each is confirmed against the view hierarchy before it
  # is typed into, and skipped if the screen has already moved on.
  $A shell uiautomator dump /sdcard/s.xml >/dev/null 2>&1
  xml=$(have cat /sdcard/s.xml)
  if [ -z "$xml" ]; then say "no view hierarchy; dumping screen"; shot signin-stuck; return 1; fi
  say "email field present: $(echo "$xml" | grep -c 'Email')"
  tap 360 631 3
  text "$GMAIL"
  key 66 14
  shot signin-after-email

  say "password"
  tap 360 538 3
  text "$GPASS"
  key 66 18
  shot signin-after-password

  # Google wants proof of the account on a device it has not seen before. The
  # order it offers varies; walk to the security code screen, which is the only
  # one a person on another device can satisfy without a smartphone in the loop.
  if [ -z "$GCODE" ]; then
    say "NO 2FA CODE STAGED -- a human is required at this screen"
    shot signin-needs-code
    pub "HUMAN NEEDED - google 2FA code screen" signin-needs-code
    say "set the PEERLINK_GCODE secret to a freshly requested code and re-dispatch"
    return 2
  fi

  for step in 1 2 3; do
    say "walking verification options (pass $step)"
    tap 171 1113 6       # TRY ANOTHER WAY
    tap 360 862 8        # second option on the list
    if have uiautomator dump /sdcard/s.xml >/dev/null 2>&1 && \
       have cat /sdcard/s.xml 2>/dev/null | grep -q "ootp-pin"; then
      say "code screen reached; typing the staged code"
      tap 360 280 3
      text "$GCODE"
      key 66 20
      signed_in && { say "SIGNED IN"; return 0; }
      sleep 8
      signed_in && { say "SIGNED IN"; return 0; }
    fi
    signed_in && { say "SIGNED IN"; return 0; }
  done
  shot signin-verification-unclear
  say "did not confirm a signed-in account"
  return 1
}

# ---------------------------------------------------------------- install ---
asset_mb() {
  # /data is root-only. A plain `adb shell du` returns nothing at all, so the
  # wait loop below never sees two equal readings, never decides the download has
  # settled, and spins for its entire budget -- reporting "?MB" the whole time.
  # That is exactly what happened on lane f. Ask through su instead, and fall
  # back to the app's own directory if the whole-filesystem read fails.
  local m
  m=$($A shell su 0 du -sm /data 2>/dev/null | tr -d '\r' | awk '{print $1}')
  if [ -z "$m" ]; then
    m=$($A shell su 0 du -sm "/data/data/$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
  fi
  printf '%s' "$m"
}

open_play_page() {
  say "opening the Play page for $PKG"
  $A shell am force-stop com.android.vending >/dev/null 2>&1
  $A shell am start -a android.intent.action.VIEW \
    -d "market://details?id=$PKG" >/dev/null 2>&1
  sleep 14
}

tap_install() {
  say "tapping Install"
  tap 360 780 12
  shot after-install-tap
  # The account-setup interstitial: continue, then skip the payment gate.
  tap 640 1180 10
  shot after-continue
  tap 640 1180 10
  shot after-skip
}

# ------------------------------------------------------------------ driver ---
say "device: $(have getprop ro.product.model)"
sign_in
rc=$?
if [ "$rc" = "2" ]; then
  say "STOPPING: needs a human for 2FA (exit 2)"
  exit 2
elif [ "$rc" != "0" ]; then
  say "sign-in did not complete; continuing to try the install anyway"
fi

open_play_page
tap_install

say "waiting for the asset packs (this is the 2026-09-30 step UM/UV)"
before=""
stable=0
for i in $(seq 1 100); do
  now=$(asset_mb)
  LAST_MB="$now"
  say "  t=$((i*20))s data=${now:-?}MB"
  # The splash can put a "Download Failed" dialog up; dismiss it so the pack
  # fetch is not blocked behind a modal.
  if have uiautomator dump /sdcard/s.xml >/dev/null 2>&1; then
    if have cat /sdcard/s.xml 2>/dev/null | grep -qi "download"; then
      tap 640 477 5
      say "  (tapped a download dialog away)"
    fi
  fi
  [ $((i % 10)) -eq 0 ] && { shot "wait-$i"; pub "asset wait ${now:-?}MB" "wait-$i"; }
  if [ -n "$before" ] && [ -n "$now" ] && [ "$now" = "$before" ]; then
    stable=$((stable+1))
  else
    stable=0
  fi
  before="$now"
  if [ "$stable" -ge 3 ] && [ -n "$now" ]; then
    say "data size stable for ${stable} checks at ${now}MB"
    break
  fi
  sleep 20
done

have pm path "$PKG" >/dev/null 2>&1
if [ $? != 0 ]; then
  say "=== $PKG IS NOT INSTALLED ==="
  shot final-not-installed
  exit 1
fi
say "installed: $(have pm path "$PKG")"

final=$(asset_mb)
say "final /data size: ${final:-?}MB"
# The base install is a few hundred MB. The packs are ~2 GB. Anything under
# 800MB means PAD never ran, and that is the failure this script exists to
# prevent -- so it is a hard failure rather than a warning.
if [ -n "$final" ] && [ "$final" -lt 800 ]; then
  say "=== ONLY ${final}MB ON DISK - PLAY ASSET DELIVERY DID NOT RUN ==="
  say "=== the game will report 'Download Failed 0%'. Stopping here. ==="
  shot final-too-small
  exit 1
fi

shot final-ok
say "assets present and stable"
exit 0
