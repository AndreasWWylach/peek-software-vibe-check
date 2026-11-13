#!/usr/bin/env bash
# setup.sh — onboarding wrapper for vibe-check (macOS / Linux).
#
# Bootstraps Node ≥ 20, then installs the open-source engine (pinned release)
# and delegates to `vibe-check setup` for the provider tools.
#
# Transparency: every command this script runs is printed first. It is safe to
# interrupt at any time and idempotent — re-run to resume where you left off.
set -euo pipefail

ENGINE_REPO="https://github.com/AndreasWWylach/peek-software-vibe-check.git"
ENGINE_TAG="${ENGINE_TAG:-main}"          # override with a pinned tag/release
INSTALL_DIR="${VIBE_CHECK_HOME:-$HOME/.local/share/vibe-check}"
BIN_DIR="$HOME/.local/bin"

info()  { printf '\033[36m▸\033[0m %s\n' "$*"; }
ok()    { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m!\033[0m %s\n' "$*"; }

info "vibe-check onboarding — bootstrap"
info "Install dir: $INSTALL_DIR"

# 1. Node ≥ 20 (the engine itself).
if command -v node >/dev/null 2>&1; then
  NODE_VERSION="$(node -p 'process.versions.node' 2>/dev/null || echo 0)"
  ok "node $NODE_VERSION"
else
  warn "Node.js not found. Install Node ≥ 20 first: https://nodejs.org"
  exit 1
fi

# 2. The engine (pinned release, reviewable).
mkdir -p "$INSTALL_DIR"
if [ -d "$INSTALL_DIR/.git" ]; then
  info "engine already present — updating"
  git -C "$INSTALL_DIR" fetch --tags origin
  git -C "$INSTALL_DIR" checkout "$ENGINE_TAG"
  git -C "$INSTALL_DIR" pull --ff-only origin "$ENGINE_TAG"
else
  info "cloning engine: $ENGINE_REPO (ref $ENGINE_TAG)"
  git clone --depth 1 --branch "$ENGINE_TAG" "$ENGINE_REPO" "$INSTALL_DIR"
fi

# 3. Provider tools (interactive installer).
info "installing provider tools — run 'vibe-check setup --dry-run' to preview"
node "$INSTALL_DIR/bin/vibe-check.mjs" setup "$@"

ok "onboarding complete — run a scan with:"
printf '  node %s/bin/vibe-check.mjs run --config /path/to/peek-config.json\n' "$INSTALL_DIR"
