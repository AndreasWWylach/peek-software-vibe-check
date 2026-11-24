# Setup — quick start

Get vibe-check installed and running in three steps.

## 1. Install the engine + tools (one command)

```bash
curl -fsSL https://raw.githubusercontent.com/AndreasWWylach/peek-software-vibe-check/main/setup.sh -o setup.sh
less setup.sh   # review before running — transparency first
bash setup.sh
```

`setup.sh` checks for Node ≥ 22 (printing the exact install command if it's
missing), clones the pinned engine release (`v0.1.0` by default — override with
`ENGINE_TAG=…`), installs its single runtime dependency, exposes `vibe-check`
on your PATH, and runs the **onboarding** to
install the provider tools (semgrep, osv-scanner, madge, scc, gitleaks, eslint, and optional checkov + hadolint + trivy + bandit + gosec + phpstan).
The **tests**, dependency-hygiene, security-headers, CSRF, wildcard-CORS, CI,
rate-limiting, Firebase and PostgreSQL/Supabase RLS providers are built into the
engine — no install. The **Semgrep PHP packs** and the **PHPStan framework extensions** (phpstan-symfony, phpstan-doctrine) are vendored in the repo — Symfony/Pimcore/Doctrine apps need only the `phpstan` PHAR, no Composer. **Laravel** is the one exception: `larastan` is not vendored (it boots the app's own Illuminate), so run `composer require --dev larastan/larastan` inside the Laravel app first. Everything prints
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

This writes `AUDIT-REPORT.md` (human), `peek-report.json` (machine), and
`FIX-PROMPTS.md` (copy-paste AI remediation prompts, one per finding group).
Every finding deep-links back to its teardown page on peek.software.

## Live deployment check (optional)

The code audit is static. To also check the **deployed** site — host/CDN
security headers, exposed `.env`/`.git`, public source maps, debug endpoints —
run:

```bash
vibe-check probe https://yourapp.com
```

Read-only GET/HEAD, bounded requests, and loopback/private targets are
rejected. Only probe sites you own. Add `--json` for machine output or
`--out <dir>` to write `probe-report.json`.

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

See `README.md` for the full CLI reference, the covered-teardown table, and the
published sample outputs (`SAMPLE-REPORT.md`, `SAMPLE-FIX-PROMPTS.md`).
