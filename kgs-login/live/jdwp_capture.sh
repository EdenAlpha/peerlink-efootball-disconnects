#!/usr/bin/env bash
# Read the gate requests in plaintext, using JDWP instead of ptrace.
#
# Why not frida-server
# --------------------
# frida-server injects by ptrace and that is precisely what fails on this
# redroid image: "Aborted (core dumped)" on 17.19.0 and 16.7.19, on spawn and on
# attach, with the server confirmed running. Retuning ptrace_scope or
# capabilities does not help, because the transport itself is the problem.
#
# frida-jdwp-loader loads the gadget over the app's JDWP debug socket instead.
# The only prerequisite is android:debuggable=true, which this APK already
# ships. No root, no repackaging, no listening port, and in script mode it runs
# autonomously inside the process and publishes via __android_log_write, which
# `adb logcat -d -s KGSHOOK` can read afterwards.
#
# Usage:  bash jdwp_capture.sh [adb-serial]
set -uo pipefail

S="${1:-127.0.0.1:5555}"
PKG=jp.konami.pesam
W=/tmp/kgs
DIR=$W/jdwp
OUT=$W/jdwp-out.txt
: > "$OUT"
say() { echo "jdwp: $*"; echo "jdwp: $*" >> "$OUT"; }

A() { adb -s "$S" "$@"; }
AS() { A shell "$@" 2>/dev/null | tr -d '\r'; }

mkdir -p "$DIR"

pid=$(AS pidof "$PKG" | awk '{print $1}')
[ -n "$pid" ] || { say "package not running"; exit 1; }
say "pid $pid"

# The one hard prerequisite, checked rather than assumed. If the app is not
# debuggable this whole route is closed and it is worth knowing in one second.
flags=$(AS dumpsys package "$PKG" | grep -iE 'DEBUGGABLE' | head -2)
say "manifest: ${flags:-<no DEBUGGABLE line found>}"
case "$flags" in
  *DEBUGGABLE*) : ;;
  *) say "NOT debuggable per dumpsys; JDWP injection will not work";;
esac

say "jdwp sockets the device is advertising:"
A shell su 0 cat /proc/net/unix 2>/dev/null | tr -d '\r' | grep -i jdwp | head -5 >> "$OUT"
A shell su 0 cat /proc/net/unix 2>/dev/null | tr -d '\r' | grep -ci jdwp | sed 's/^/  count=/' >> "$OUT"

# adb jdwp lists attachable processes; an entry for our pid means JDWP is live.
say "adb jdwp list:"
A jdwp 2>&1 | head -8 | tee -a "$OUT"

if [ ! -d "$DIR/frida-jdwp-loader/.git" ]; then
  say "fetching frida-jdwp-loader"
  git clone --depth 1 -q https://github.com/frankheat/frida-jdwp-loader.git \
    "$DIR/frida-jdwp-loader" >>"$OUT" 2>&1 || {
      say "CLONE FAILED"; exit 1; }
fi

HOOK=$W/jdwp_gate_hook.js
if [ ! -s "$HOOK" ]; then
  say "fetching the hook"
  curl -fsSL --max-time 60 \
    https://raw.githubusercontent.com/EdenAlpha/peerlink-efootball-disconnects/main/kgs-login/scripts/jdwp_gate_hook.js \
    -o "$HOOK" || { say "HOOK FETCH FAILED"; exit 1; }
fi
say "hook bytes: $(wc -c < "$HOOK")"

# Script interaction mode: the gadget is loaded over JDWP, runs our script
# inside the process, and never opens a port. -a names the launcher activity
# because this app's entry point is an Epic splash, not a plain launcher.
say "injecting (this restarts the app; the game will be respawned under the hook)"
cd "$DIR/frida-jdwp-loader" || exit 1
timeout 420 python3 frida-jdwp-loader.py frida \
  -n "$PKG" \
  -a com.epicgames.ue4.SplashActivity \
  -i script \
  -l "$HOOK" \
  -m spawn \
  -v >>"$OUT" 2>&1
rc=$?
say "loader rc=$rc"

sleep 20
say "=== logcat KGSHOOK ==="
A logcat -d -s KGSHOOK 2>/dev/null | tr -d '\r' | tail -60 | tee -a "$OUT"

hits=$(grep -c 'BODY\[' "$OUT" 2>/dev/null || echo 0)
keys=$(grep -c 'KEY ' "$OUT" 2>/dev/null || echo 0)
say "plaintext bodies seen: $hits   keys seen: $keys"
say "full log: $OUT"
exit 0
