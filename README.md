# vibe-check

Open-source, local deep-scan engine for [peek.software](https://peek.software). It turns Peek's teardown catalog into an executable audit of your codebase — running **entirely on your machine, against your own source code**.

> **Status:** Phase 1 skeleton. The provider pipeline (Semgrep + OSV-Scanner) is wired end-to-end; the 8-rule golden rulepack lands in Phase 2. See `docs/deep-scan-engine.md` for the full design.

## Trust statement

1. **Zero telemetry.** The engine never calls peek.software.
2. **Offline & deterministic.** Only the OSV CVE lookup touches the network.
3. **Inert config.** `peek-config.json` is schema-validated data — never executed code.
4. **Open & reviewable.** Apache-2.0. No hidden actions.

## Prerequisites

- Node.js ≥ 22
- [semgrep](https://semgrep.dev) — custom teardown rules (core)
- [osv-scanner](https://google.github.io/osv-scanner) **v2** — dependency CVEs (core)
- [madge](https://github.com/pahen/madge) — circular-dependency graph → architecture findings (core)
- [scc](https://github.com/boyter/scc) — file-size metrics → monolithic-file findings (core)
- [gitleaks](https://github.com/gitleaks/gitleaks) — secrets → hardcoded-secret findings (core)
- [eslint](https://eslint.org) **9** — language linter → QA hygiene findings (core)

A missing binary is reported as **"skipped"** in the report — never a failure. The engine degrades gracefully.

## Usage

```bash
git clone https://github.com/AndreasWWylach/peek-software-vibe-check.git
cd peek-software-vibe-check
npm install
node bin/vibe-check.mjs run --config /path/to/peek-config.json
```

This writes `AUDIT-REPORT.md` (human) and `peek-report.json` (machine) into the current directory.

### Onboarding (installer)

One command gets the machine ready — no two-mile setup guide. Every install is
shown (command + source + checksum) before it runs, and is interruptible and
idempotent:

```bash
vibe-check doctor                 # read-only: what's installed / missing / outdated
vibe-check setup                  # interactive installer (y/n/skip per tool)
vibe-check setup --dry-run        # print every planned step, install nothing
vibe-check setup --yes            # non-interactive (accept everything)
vibe-check setup --skip madge     # skip a tool
```

Or bootstrap everything from a shell (installs Node, the engine, then runs the
onboarding):

```bash
curl -fsSL https://raw.githubusercontent.com/AndreasWWylach/peek-software-vibe-check/main/setup.sh -o setup.sh
less setup.sh   # review before running — transparency first
bash setup.sh
```

### CLI

| Command | Description |
| --- | --- |
| `vibe-check run --config <path>` | Run the scan against a `peek-config.json` |
| `vibe-check run --config <path> --out <dir>` | Write reports to `<dir>` |
| `vibe-check run --config <path> --quiet` | Suppress progress output |
| `vibe-check doctor` | Read-only onboarding check |
| `vibe-check setup` | Interactive onboarding (installs the tools) |
| `vibe-check --version` | Print the engine version |
| `vibe-check --help` | Print help |

## Development

```bash
npm test             # node:test — unit + parser + golden + integration tests
npm run typecheck    # tsc --noEmit (JSDoc type-checked, @ts-check)
```

Install the six provider binaries to run the full suite (unit + parser tests run
without them; golden + integration tests skip when a binary is missing):

```bash
pipx install semgrep
npm install -g madge
npm install -g eslint@9
# scc (Linux amd64):
curl -sSL -o /tmp/scc.tar.gz \
  https://github.com/boyter/scc/releases/download/v3.5.0/scc_Linux_x86_64.tar.gz
tar -xzf /tmp/scc.tar.gz -C /tmp
install -m 0755 /tmp/scc ~/.local/bin/scc
# gitleaks (Linux amd64):
curl -sSL -o /tmp/gitleaks.tar.gz \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C /tmp
install -m 0755 /tmp/gitleaks ~/.local/bin/gitleaks
# osv-scanner v2 (Linux amd64):
curl -sSL -o ~/.local/bin/osv-scanner \
  https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64
chmod +x ~/.local/bin/osv-scanner
```

- **Golden tests** (`tests/golden.test.mjs`) run each custom Semgrep rule against
  its teardown's `vulnerableCode` (must fire) and `hardenedCode` (must stay silent).
- **Integration test** (`tests/integration.test.mjs`) runs the full engine against
  a checked-in sample app and asserts the report.
- CI (`.github/workflows/ci.yml`) installs both tools and runs typecheck + tests
  on every push.

## Layout

```
bin/            CLI entry
src/            engine — config, scoring, providers, report
schema/         published JSON Schema contracts (config + report)
catalog/        vendored teardown facts snapshot
rules/          custom Semgrep rules — one per (TD × language)
examples/       sample app used by the integration test
tests/          unit, parser, golden, and integration tests
```

## License

Apache-2.0 — see `LICENSE`.
