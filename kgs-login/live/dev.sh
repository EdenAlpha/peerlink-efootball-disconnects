#!/usr/bin/env bash
# Device access layer so the SAME live-control loop can drive either
#   redroid (docker, on the Linux runner)   DEV_MODE=docker
#   the Android emulator or a real device   DEV_MODE=adb  (default)
#
# Why: the community-standard Play emulator (reactivecircus on macOS) speaks
# adb, not docker. Rather than maintain two loops, every device call goes
# through these helpers and the mode decides the transport. The tap/screenshot
# round-trip is identical either way - the operator sees no difference.
#
# Sourced by live_loop.sh; never run directly.

DEV_MODE="${DEV_MODE:-adb}"
CONTAINER="${CONTAINER:-redroid}"
ADB="${ADB:-adb}"

# run a shell command on the device
dev_sh() {
  if [ "$DEV_MODE" = "adb" ]; then
    $ADB shell "$*" 2>/dev/null | tr -d '\r'
  else
    sudo docker exec "$CONTAINER" sh -c "$*" 2>/dev/null | tr -d '\r'
  fi
}

# screenshot into a host path ($1)
dev_shot() {
  if [ "$DEV_MODE" = "adb" ]; then
    $ADB exec-out screencap -p > "$1" 2>/dev/null || true
  else
    sudo docker exec "$CONTAINER" sh -c \
      'screencap -p /data/local/tmp/live_shot.png' >/dev/null 2>&1
    sudo docker cp "$CONTAINER:/data/local/tmp/live_shot.png" "$1" \
      2>/dev/null || true
  fi
}

# game process id (first word) or empty
dev_pid() {
  dev_sh 'pidof jp.konami.pesam' | awk '{print $1}'
}

dev_tap() { # $1=x $2=y
  dev_sh "/system/bin/input tap $1 $2" >/dev/null 2>&1
}

dev_amstart() { # $1 = component
  dev_sh "am start -W -n $1"
}

dev_intent() { # $1 = uri
  dev_sh "am start -a android.intent.action.VIEW -d '$1'"
}

# full clickable-node dump to $1 (geometry for aiming)
dev_uidump() {
  bash kgs-login/scripts/uidump_mac.sh "$1" 2>/dev/null \
    || bash kgs-login/scripts/uidump.sh "$CONTAINER" "$1" 2>/dev/null
}

# tap by node text ($1 = regex)
dev_uitap() {
  if [ "$DEV_MODE" = "adb" ]; then
    bash kgs-login/scripts/uitap_mac.sh "$1" 2>/dev/null
  else
    bash kgs-login/scripts/uitap.sh "$CONTAINER" "$1" 2>/dev/null
  fi
}
