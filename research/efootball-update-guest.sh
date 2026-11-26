#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s {prepare|launch} CACHE_DIRECTORY\n' "$0" >&2
  exit 2
}

[[ $# == 2 && ( $1 == prepare || $1 == launch ) ]] || usage
mode=$1
cache=$(realpath -m "$2")
research=$(cd "$(dirname "$0")" && pwd)
manifest="$research/efootball-11.1.1-guest.sha256"
assets="$research/efootball_guest_assets.py"

if [[ "$mode" == prepare ]]; then
  mkdir -p "$(dirname "$cache")"
  exec 9>"$cache.lock"
  flock 9
  if [[ -d "$cache" ]] && python3 "$assets" verify "$cache" "$manifest"; then
    echo 'Using the verified eFootball 11.1.1 cache.'
    exit 0
  fi

  temporary=$(mktemp -d "$(dirname "$cache")/efootball-cache.XXXXXXXX")
  trap 'rm -rf -- "$temporary"' EXIT
  source_repo=EdenAlpha/peerlink-efootball-disconnects
  gh release download game-full-20261012 --repo "$source_repo" \
    --pattern 'game-data.tar.part-a[ab]' --dir "$temporary"
  (
    cd "$temporary"
    sha256sum --check --strict <<'CHECKSUMS'
14dd93970e74ffd37eec8e8550429fbdad65552a9f768b6ac65a3cfed2395ebd  game-data.tar.part-aa
a146f20a147f0924fa8d5d6e0c26b38dbaab371ec5f4c9268e36c29dc477d194  game-data.tar.part-ab
CHECKSUMS
  )
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 380 --retry 2 \
    'https://d.apkpure.net/b/XAPK/jp.konami.pesam?versionCode=311010101' \
    --output "$temporary/reference.xapk"

  cat "$temporary"/game-data.tar.part-{aa,ab} |
    python3 "$assets" extract "$temporary/verified" "$manifest" "$temporary/reference.xapk"
  if [[ -e "$cache" ]]; then
    previous=$(mktemp -d "$cache.previous.XXXXXXXX")
    mv -T -- "$cache" "$previous/cache"
    printf 'Moved the incomplete cache to %s\n' "$previous/cache"
  fi
  mv -T -- "$temporary/verified" "$cache"
  echo 'Saved the verified eFootball 11.1.1 cache.'
  exit 0
fi

python3 "$assets" verify "$cache" "$manifest"
phone=redroid-update-guest
device=127.0.0.1:15557
game=jp.konami.pesam
image=edwardzhouquan/redroid-mindthegapps-arm64@sha256:119cec40899eca55794964a0a9813663b97e5a64202e3fc53e939713ecdce98a
android() { adb -s "$device" shell "$@"; }
guest() { sudo docker exec "$phone" "$@"; }

if ! sudo docker container inspect "$phone" >/dev/null 2>&1; then
  sudo docker run -d --name "$phone" --privileged -p "$device:5555" "$image" \
    androidboot.redroid_width=1280 androidboot.redroid_height=720 \
    androidboot.redroid_dpi=240 androidboot.use_memfd=true >/dev/null
else
  sudo docker start "$phone" >/dev/null
fi

for attempt in $(seq 1 70); do
  state=$(guest getprop sys.boot_completed 2>/dev/null | tr -d '\r') || state=
  [[ "$state" == 1 ]] && break
  sleep 3
done
[[ "$state" == 1 ]] || { echo 'The update guest did not boot.' >&2; exit 1; }
adb connect "$device" >/dev/null
accounts=$(android dumpsys account)
if ! grep -Eq '^[[:space:]]*Accounts: 0[[:space:]]*$' <<< "$accounts" ||
    grep -Eq '^[[:space:]]*Accounts: [1-9][0-9]*[[:space:]]*$' <<< "$accounts"; then
  echo 'Use a fresh Android guest with zero configured accounts.' >&2
  exit 1
fi
android settings put secure backup_auto_restore 0
android wm size 640x360
android wm density 120

if ! packages=$(android pm path "$game") || [[ "$packages" != package:* ]]; then
  adb -s "$device" install-multiple "$cache"/apks/*.apk
fi
game_version=$(android dumpsys package "$game")
grep -Eq 'versionCode=311010101([[:space:]]|$)' <<< "$game_version" || {
  echo 'The guest has a different eFootball build. Use a fresh guest for 11.1.1.' >&2
  exit 1
}

game_dir="/data/user/0/$game/files"
marker=/data/local/tmp/peerlink-efootball-11.1.1-packs
if ! guest test -f "$marker"; then
  android am start -W -n "$game/com.epicgames.ue4.SplashActivity"
  for attempt in $(seq 1 20); do
    guest test -d "$game_dir" && break
    sleep 1
  done
  guest test -d "$game_dir"
  android am force-stop "$game"
  staging=$(guest mktemp -d /data/local/tmp/efootball-packs.XXXXXXXX)
  trap 'guest rm -rf -- "$staging"' EXIT
  sudo docker cp "$cache/verified-packs/." "$phone:$staging/"
  guest sh -c '
    set -eu
    game_dir=$1
    staging=$2
    marker=$3
    owner=$(stat -c "%u:%g" "$game_dir")
    mkdir -p "$game_dir/assetpacks"
    cp -a "$staging/." "$game_dir/assetpacks/"
    chown -R "$owner" "$game_dir/assetpacks"
    restorecon -RF "$game_dir/assetpacks" 2>/dev/null || true
    touch "$marker"
  ' sh "$game_dir" "$staging" "$marker"
fi

android am start -W -n "$game/com.epicgames.ue4.SplashActivity"
echo "eFootball 11.1.1 update guest ready at $device."
