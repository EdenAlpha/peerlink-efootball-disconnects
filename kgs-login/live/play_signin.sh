#!/usr/bin/env bash
# Sign the burner account into the real Play Store on the container phone.
#
# Why a script and not taps: the whole screen sequence was discovered by hand
# over an hour of round trips, and it is identical on every fresh phone. Doing
# it here means a new session needs ONE thing from the operator (the security
# code) instead of ten taps.
#
# Coordinates are from the 720x1280 screenshots in kgs-login/evidence and were
# read off the actual screen, not guessed.
#
# Usage:  bash kgs-login/live/play_signin.sh <adb-serial>
# Stops on the "enter code" screen and prints WHERE_TO_TYPE so the operator can
# paste a fresh security code, then finishes on a second call with `code <n>`.
set -uo pipefail

S="${1:-127.0.0.1:5555}"
A="adb -s $S"
say() { echo "signin: $*"; }

adb_() { $A shell "$@" 2>/dev/null | tr -d '\r'; }
shot()  { $A exec-out screencap -p > "$1" 2>/dev/null; }

say "opening the Play Store"
$A shell am force-stop com.android.vending >/dev/null 2>&1
$A shell am start -W -n com.android.vending/com.google.android.finsky.activities.MainActivity >/dev/null 2>&1
sleep 12

# Sign in button on the unauthenticated landing page.
say "tapping Sign in"
$A shell input tap 360 907 >/dev/null 2>&1
sleep 14

# Email field on the Google sign-in page.
say "typing the email"
$A shell input tap 360 631 >/dev/null 2>&1
sleep 3
$A shell input text "$PEERLINK_GMAIL" >/dev/null 2>&1
sleep 2
$A shell input keyevent 66 >/dev/null 2>&1
sleep 14

# Password field. If the account is already signed in, or the code screen is
# reached immediately, this is a no-op and the operator sees where we are.
say "typing the password"
$A shell input tap 360 538 >/dev/null 2>&1
sleep 3
$A shell input text "$PEERLINK_GPASS" >/dev/null 2>&1
sleep 2
$A shell input keyevent 66 >/dev/null 2>&1
sleep 18

# Google now wants proof of the account on this new device. The order it
# offers is: phone-number SMS, then a passkey, then "last password", and
# finally a Security code read off the account owner's own phone. Walk to the
# Security code screen; every step is idempotent, so an extra tap is harmless.
for step in 1 2 3; do
  say "walking the verification options (pass $step)"
  $A shell input tap 171 1113 >/dev/null 2>&1   # TRY ANOTHER WAY
  sleep 6
  $A shell input tap 360 862 >/dev/null 2>&1    # second option on the list
  sleep 8
  # If a code field exists, stop and let the operator type it.
  if $A shell uiautomator dump /sdcard/s.xml >/dev/null 2>&1; then
    if $A shell cat /sdcard/s.xml 2>/dev/null | grep -q "ootp-pin"; then
      say "CODE SCREEN REACHED - operator must paste a fresh security code"
      say "then run:  bash $0 $S code <the-code>"
      exit 0
    fi
  fi
done
say "did not reach a code screen; dumping the screen for inspection"
shot /tmp/live-res/screen.png
echo "signin: NEEDS-HUMAN"
