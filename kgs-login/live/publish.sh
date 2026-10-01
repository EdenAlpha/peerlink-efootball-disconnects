#!/usr/bin/env bash
# Publish a progress note and a screenshot to the live-res branch from OUTSIDE
# the live loop.
#
# Why this exists: `gh run view --log` refuses to return anything while a run is
# in progress, and the live control loop does not start until step 05. So during
# the Play sign-in and the ~45 minute asset download there was no way to see
# what the phone was doing except to wait three hours for the job to end. This
# makes those steps observable, which is the difference between watching a
# screen sequence and guessing at it.
#
# Every git call is time-boxed for the reason given in live_loop.sh: an
# unbounded push on a runner that wants a credential prompt hangs forever and
# looks exactly like slow progress from the outside.
#
# Usage:  bash publish.sh <label> [screenshot.png]
set -uo pipefail

LABEL="${1:-progress}"
SHOT="${2:-}"
DIR=/tmp/live-res
BRANCH=live-res

[ -e "$DIR/.git" ] || { echo "publish: no worktree at $DIR"; exit 2; }

cd "$DIR" || exit 2

if [ -n "$SHOT" ] && [ -s "$SHOT" ]; then
  cp -f "$SHOT" "$DIR/pub.png"
fi

if timeout 60 git add -A >/dev/null 2>&1 && \
   timeout 60 git diff --cached --quiet >/dev/null 2>&1; then
  echo "publish: nothing new ($LABEL)"
  exit 0
fi

for attempt in 1 2 3; do
  if timeout 60 git -c user.name="live-bot" \
       -c user.email="live-bot@users.noreply.github.com" \
       commit -qm "install: $LABEL" >/dev/null 2>&1; then
    if timeout 120 git push origin "HEAD:refs/heads/$BRANCH" >/dev/null 2>&1; then
      echo "publish: pushed $LABEL"
      exit 0
    fi
  fi
  echo "publish: attempt $attempt failed ($LABEL); rebasing"
  timeout 120 git fetch origin "$BRANCH" >/dev/null 2>&1 || true
  timeout 60 git rebase "origin/$BRANCH" >/dev/null 2>&1 || \
    timeout 60 git reset --hard "origin/$BRANCH" >/dev/null 2>&1 || true
  sleep 3
done

echo "publish: PUSH FAILED after 3 attempts ($LABEL)"
exit 1
