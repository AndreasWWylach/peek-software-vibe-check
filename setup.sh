#!/usr/bin/env bash
# This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
# SPDX-License-Identifier: Apache-2.0

# setup.sh — onboarding wrapper for vibe-check (macOS / Linux).
#
# Requires Node ≥ 22 (prints the exact install command if it's missing), then
# installs the open-source engine (pinned release), its single runtime
# dependency, and exposes the `vibe-check` command on PATH. Finally it
# delegates to `vibe-check setup` for the provider tools.
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

# 1. Node ≥ 22 (the engine itself).
if command -v node >/dev/null 2>&1; then
  NODE_VERSION="$(node -p 'process.versions.node' 2>/dev/null || echo 0)"
  NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  if [ "$NODE_MAJOR" -lt 22 ]; then
    warn "Node.js $NODE_VERSION is too old — vibe-check needs Node ≥ 22."
    if command -v nvm >/dev/null 2>&1 || [ -s "$HOME/.nvm/nvm.sh" ]; then
      warn "  nvm found — run: nvm install 22 && nvm use 22"
    else
      warn "  install Node ≥ 22: https://nodejs.org (or: curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs)"
    fi
    exit 1
  fi
  ok "node $NODE_VERSION"
else
  warn "Node.js not found — vibe-check needs Node ≥ 22: https://nodejs.org"
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

# 3. Engine dependencies (a single runtime dep: ajv). Without this, `vibe-check
#    run` crashes on a fresh clone.
info "installing engine dependencies (npm ci --omit=dev)"
( cd "$INSTALL_DIR" && npm ci --omit=dev --no-audit --no-fund )

# 4. Expose the `vibe-check` command on your PATH.
chmod +x "$INSTALL_DIR/bin/vibe-check.mjs"
mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/bin/vibe-check.mjs" "$BIN_DIR/vibe-check"
case ":$PATH:" in
  *":$BIN_DIR:"*) ok "vibe-check → $BIN_DIR (on PATH)" ;;
  *) warn "$BIN_DIR is not on your PATH — add it:"; warn "  export PATH=\"$BIN_DIR:\$PATH\"   (or add to ~/.bashrc / ~/.zshrc)" ;;
esac

# 5. Provider tools (interactive installer).
info "installing provider tools — run 'vibe-check setup --dry-run' to preview"
node "$INSTALL_DIR/bin/vibe-check.mjs" setup "$@"

ok "onboarding complete — run a scan with:"
printf '  vibe-check run --config /path/to/peek-config.json\n'
