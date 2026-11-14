# Setup — quick start

Get vibe-check installed and running in three steps.

## 1. Install the engine + tools (one command)

```bash
curl -fsSL https://raw.githubusercontent.com/AndreasWWylach/peek-software-vibe-check/main/setup.sh -o setup.sh
less setup.sh   # review before running — transparency first
bash setup.sh
```

`setup.sh` checks for Node ≥ 22 (printing the exact install command if it's
missing), clones the pinned engine release, installs its single runtime
dependency, exposes `vibe-check` on your PATH, and runs the **onboarding** to
install the provider tools (semgrep, osv-scanner, madge, scc, gitleaks, eslint).
The **tests** signal is built into the engine — no install. Everything prints
before it runs, and you can interrupt at any time — re-run to resume.

## 2. Get your config

On [peek.software](https://peek.software), complete the manifest intake and click
**Download scan config** — or write one by hand:

```json
{
  "version": 1,
  "engine": ">=0.1.0",
  "targets": ["src/"],
  "languages": ["typescript"],
  "enabledRules": ["TD-016", "TD-045"]
}
```

## 3. Run the scan

```bash
vibe-check run --config peek-config.json
```

This writes `AUDIT-REPORT.md` (human) and `peek-report.json` (machine). Every
finding deep-links back to its teardown page on peek.software.

## Useful checks

```bash
vibe-check doctor                 # read-only: what's installed / missing / outdated
vibe-check setup --dry-run        # preview every planned install, run nothing
vibe-check setup --skip madge     # skip a specific tool
```

## Manual install (no setup.sh)

```bash
git clone https://github.com/AndreasWWylach/peek-software-vibe-check.git
cd peek-software-vibe-check
npm install
vibe-check setup    # or: node bin/vibe-check.mjs setup
```

See `README.md` for the full CLI reference and `docs/deep-scan-engine.md` for the
design.
