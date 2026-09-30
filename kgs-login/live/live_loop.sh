#!/usr/bin/env bash
# Live control loop: lets a human drive the phone in near-real-time.
#
# Why this exists instead of a tunnel: GitHub runners accept no inbound
# connections, so adb cannot be reached from outside. Instead the two sides
# rendezvous through two branches that never conflict, because each side only
# ever WRITES one of them:
#
#   live-cmd  operator -> runner   (a single file, cmd.txt, one command)
#   live-res  runner   -> operator (screenshots, dumps, logs)
#
# A round trip takes 30-60 seconds: slow enough to feel deliberate, fast
# enough to tap through a setup screen in minutes instead of blind 35-minute
# runs. Every command and every result is committed, so the whole session is
# an audit trail.
#
# Commands (one per line in live-cmd/cmd.txt, first line wins):
#   tap X Y        touch the screen there, then screenshot
#   shot [name]    screenshot only
#   uidump         full clickable-node dump (geometry for aiming)
#   uitap REGEX    tap by node text (works on native UI, not Compose)
#   amstart COMP   am start -W -n COMP (launch an activity)
#   intent URI     am start -a VIEW -d URI
#   exec SH...     run shell on the host (proxy, CA, dumps -- logged verbatim)
#   flows [N]      tail N lines of the decrypted-flows log
#   status         heartbeat on demand
#   quit           end the session (falls through to publish/upload)
#
# Results go to live-res/results/NNN/ (out.txt + shot_N.png + ui_N.xml).
# live-res/status.txt is a heartbeat: time, game alive?, flows seen.
set -uo pipefail

CONTAINER="redroid"
: "${W:=/tmp/kgs}"
: "${LIVE_RES_DIR:=/tmp/live-res}"
: "${POLL_SECS:=8}"
: "${HEARTBEAT_EVERY:=15}"
: "${MAX_ROUNDS:=1400}"

say() { echo "live: $*"; }

shot_to() { # $1 = dest png path on host
  sudo docker exec "$CONTAINER" sh -c \
    'screencap -p /data/local/tmp/live_shot.png' >/dev/null 2>&1
  sudo docker cp "$CONTAINER:/data/local/tmp/live_shot.png" "$1" \
    2>/dev/null || true
}

game_alive() {
  sudo docker exec "$CONTAINER" sh -c \
    'pidof jp.konami.pesam 2>/dev/null' 2>/dev/null | tr -d '\r' | awk '{print $1}'
}

flows_seen() { { grep -c '^### ' "$W/flows.log" 2>/dev/null || echo 0; } | head -1; }

push_res() { # commit + push whatever is staged in LIVE_RES_DIR
  cd "$LIVE_RES_DIR" || return 1
  git add -A >/dev/null 2>&1
  if git diff --cached --quiet >/dev/null 2>&1; then return 0; fi
  git -c user.name="live-bot" -c user.email="live-bot@users.noreply.github.com" \
    commit -qm "live: $1" || return 1
  git push origin HEAD:refs/heads/live-res >/dev/null 2>&1 || \
    { git pull --rebase origin live-res >/dev/null 2>&1 || true;
      git push origin HEAD:refs/heads/live-res >/dev/null 2>&1 || true; }
  cd - >/dev/null 2>&1 || true
  return 0
}

heartbeat() {
  local alive flows
  alive=$(game_alive); flows=$(flows_seen)
  { echo "time=$(date -u +%H:%M:%S)";
    echo "gamepid=${alive:-none}";
    echo "flows=$flows";
    echo "round=$1"; } > "$LIVE_RES_DIR/status.txt"
  push_res "heartbeat $1" || true
}

run_cmd() { # $1 = round dir, $2... = command words
  local dir="$1"; shift
  local verb="$1"; shift || true
  local out="$dir/out.txt"
  { echo "cmd: $verb $*"; echo "at: $(date -u +%H:%M:%S)"; } > "$out"
  case "$verb" in
    tap)
      sudo docker exec "$CONTAINER" /system/bin/input tap "$1" "$2" \
        >/dev/null 2>&1
      echo "tapped ($1,$2)" >> "$out"
      shot_to "$dir/shot.png"
      ;;
    shot)
      shot_to "$dir/shot.png"
      echo "screenshot only" >> "$out"
      ;;
    uidump)
      bash kgs-login/scripts/uidump.sh "$CONTAINER" "$dir/ui.xml" \
        >> "$out" 2>&1 || echo "uidump failed (see out)" >> "$out"
      shot_to "$dir/shot.png"
      ;;
    uitap)
      bash kgs-login/scripts/uitap.sh "$CONTAINER" "$1" >> "$out" 2>&1 \
        || echo "uitap missed" >> "$out"
      shot_to "$dir/shot.png"
      ;;
    amstart)
      sudo docker exec "$CONTAINER" sh -c "am start -W -n $1" \
        >> "$out" 2>&1
      sleep 5
      shot_to "$dir/shot.png"
      ;;
    intent)
      sudo docker exec "$CONTAINER" sh -c \
        "am start -a android.intent.action.VIEW -d '$1'" >> "$out" 2>&1
      sleep 5
      shot_to "$dir/shot.png"
      ;;
    exec)
      # shell on the HOST (proxy, CA, dumps). Logged verbatim for the audit.
      echo "\$ $*" >> "$out"
      eval "$*" >> "$out" 2>&1
      echo "rc=$?" >> "$out"
      ;;
    flows)
      tail -"${1:-40}" "$W/flows.log" >> "$out" 2>&1 \
        || echo "no flows.log yet" >> "$out"
      ;;
    status)
      echo "on demand heartbeat" >> "$out"
      ;;
    quit)
      echo "QUIT received" >> "$out"
      return 2
      ;;
    *)
      echo "UNKNOWN VERB: $verb" >> "$out"
      ;;
  esac
  { echo "gamepid: $(game_alive)";
    echo "flows: $(flows_seen)"; } >> "$out"
  return 0
}

main() {
  mkdir -p "$W" "$LIVE_RES_DIR"
  say "live control loop starting (poll ${POLL_SECS}s, max ${MAX_ROUNDS} rounds)"
  say "write commands to live-cmd/cmd.txt ; read live-res/results + status.txt"
  local last="" round=0 since_hb=0 rc=0
  heartbeat 0
  while [ "$round" -lt "$MAX_ROUNDS" ]; do
    round=$((round + 1))
    since_hb=$((since_hb + 1))
    git fetch origin live-cmd >/dev/null 2>&1 || true
    cmd=$(git show origin/live-cmd:cmd.txt 2>/dev/null | head -1 | tr -d '\r')
    if [ -n "$cmd" ] && [ "$cmd" != "$last" ]; then
      last="$cmd"
      dir="$LIVE_RES_DIR/results/$(printf %04d $round)"
      mkdir -p "$dir"
      # shellcheck disable=SC2086
      run_cmd "$dir" $cmd
      rc=$?
      push_res "round $round: $cmd"
      [ "$rc" = "2" ] && { say "quit received, ending loop"; break; }
      since_hb=0
    elif [ "$since_hb" -ge "$HEARTBEAT_EVERY" ]; then
      heartbeat "$round"
      since_hb=0
    fi
    sleep "$POLL_SECS"
  done
  heartbeat "end"
  say "loop ended after $round rounds"
}

main
