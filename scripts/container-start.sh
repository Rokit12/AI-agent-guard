#!/bin/sh
# Container entrypoint for hosting Agent Shield (Amazon ECS on Fargate, or any container host).
#  - DATA_DIR: persistent storage (EFS). Alerts, emails and logs live there, so they survive restarts.
#  - TARGET_REPO: the agent's git repository. It is cloned on start and pulled every 30 minutes,
#    and its packages are installed without running any install scripts.
set -eu
cd "$(dirname "$0")/.."
APP="$(pwd)"

if [ -n "${DATA_DIR:-}" ]; then
  for d in state outbox logs; do
    mkdir -p "$DATA_DIR/$d"
    rm -rf "$APP/$d" && ln -s "$DATA_DIR/$d" "$APP/$d"
  done
fi

if [ -n "${TARGET_REPO:-}" ]; then
  T="${TARGET_DIR:-$APP/target}"
  if [ -d "$T/.git" ]; then git -C "$T" pull -q --ff-only || true
  else git clone -q "$TARGET_REPO" "$T"; fi
  # packages for the supply-chain, malware and outdated-software scans; --ignore-scripts: never run their code
  ( cd "$T" && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error >/tmp/target-install.log 2>&1 || true ) &
  ( while sleep 1800; do git -C "$T" pull -q --ff-only >/dev/null 2>&1 || true; done ) &
fi

exec npx tsx src/server.ts
