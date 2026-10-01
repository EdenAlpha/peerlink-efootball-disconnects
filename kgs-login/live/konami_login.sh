#!/usr/bin/env bash
# Open the Konami login: hamburger, Data Transfer, then read the browser page.
#
# Why Data Transfer
# -----------------
# The hamburger menu holds only Legal and Privacy, General Contact, Data
# Transfer, Graphics, Clear Cache and Delete Live Update. There is no login entry
# on the title screen -- confirmed on two separate devices. Data Transfer is the
# route to Konami-ID, and the login itself is a browser OAuth flow, which matches
# the app's own code:
#
#     jp.konami.android.common.KonamiId -- the auth code arrives by deep link
#         konamiid://...?code=<CODE>
#
# So the password goes browser to Konami and never appears in the game's traffic.
# After authenticating, the redirect is a custom-scheme intent rather than a page
# load, so a pause with nothing visible on screen is expected rather than a
# failure.
#
# Why the UI dump matters
# ----------------------
# The game's own UI is a UE4 SurfaceView and uiautomator sees nothing in it, which
# is why every in-game tap this session has been by coordinate. The browser page
# is ordinary Android views, so it CAN be read: the dump is taken so the email
# and password fields are found by their real bounds instead of by a guess.
#
# Usage:  bash konami_login.sh [adb-serial]
set -uo pipefail

S="${1:-127.0.0.1:5555}"
A="adb -s $S"
OUT=/tmp/live-res
mkdir -p "$OUT"
say() { echo "login: $*"; }

shot() { $A exec-out screencap -p > "$OUT/screen.png" 2>/dev/null; }

hold() { $A shell input swipe "$1" "$2" "$1" "$2" 250 >/dev/null 2>&1; }

say "opening the hamburger at (1207, 661)"
hold 1207 661
sleep 14
shot
say "  menu screenshot taken"

say "tapping Data Transfer at (925, 362)"
hold 925 362
sleep 18
shot
say "  screenshot taken after Data Transfer"

# What is in the foreground now? This tells us whether a browser opened at all,
# which is the thing most likely to go wrong: the container's only https handler
# is org.chromium.webview_shell, and if the deep link has no registered target
# the app may simply sit there.
say "=== foreground activity ==="
$A shell dumpsys window 2>/dev/null | tr -d '\r' | grep -iE 'mCurrentFocus|mFocusedApp' | head -3

say "=== https handler on this device ==="
$A shell cmd package resolve-activity --brief -a android.intent.action.VIEW -d "https://example.com" 2>/dev/null | tr -d '\r' | tail -2

# The konamiid scheme is how the OAuth code comes back. If nothing handles it the
# login will appear to do nothing, and that is worth knowing rather than guessing.
say "=== konamiid:// handler ==="
$A shell cmd package resolve-activity --brief -a android.intent.action.VIEW -d "konamiid://x?code=y" 2>/dev/null | tr -d '\r' | tail -2

say "=== browser page fields ==="
if $A shell uiautomator dump /sdcard/s.xml >/dev/null 2>&1; then
  $A shell cat /sdcard/s.xml > "$OUT/browser.xml" 2>/dev/null
  tr '>' '\n' < "$OUT/browser.xml" | grep -iE 'EditText|password|email|sign|log ?in|continue|next' | head -14
  say "  full dump at $OUT/browser.xml"
else
  say "  no view hierarchy -- the foreground is not a normal view hierarchy"
fi

say "done; screenshot at $OUT/screen.png"
exit 0
