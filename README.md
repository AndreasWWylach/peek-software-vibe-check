# vibe-check

Open-source, local deep-scan engine for [peek.software](https://peek.software). It turns Peek's teardown catalog into an executable audit of your codebase — running **entirely on your machine, against your own source code**.

> **Status:** Phase 1 skeleton. The provider pipeline (Semgrep + OSV-Scanner) is wired end-to-end; the 8-rule golden rulepack lands in Phase 2. See `docs/deep-scan-engine.md` for the full design.

## Trust statement

1. **Zero telemetry.** The engine never calls peek.software.
2. **Offline & deterministic.** Only the OSV CVE lookup touches the network.
3. **Inert config.** `peek-config.json` is schema-validated data — never executed code.
4. **Open & reviewable.** Apache-2.0. No hidden actions.

## Prerequisites

- Node.js ≥ 20
- [semgrep](https://semgrep.dev) — custom teardown rules (core)
- [osv-scanner](https://google.github.io/osv-scanner) **v2** — dependency CVEs (core)
- [madge](https://github.com/pahen/madge) — circular-dependency graph → architecture findings (core)

A missing binary is reported as **"skipped"** in the report — never a failure. The engine degrades gracefully.

## Usage

```bash
git clone https://github.com/AndreasWWylach/peek-software-vibe-check.git
cd peek-software-vibe-check
npm install
node bin/vibe-check.mjs run --config /path/to/peek-config.json
```

This writes `AUDIT-REPORT.md` (human) and `peek-report.json` (machine) into the current directory.

### CLI

| Command | Description |
| --- | --- |
| `vibe-check run --config <path>` | Run the scan against a `peek-config.json` |
| `vibe-check run --config <path> --out <dir>` | Write reports to `<dir>` |
| `vibe-check run --config <path> --quiet` | Suppress progress output |
| `vibe-check --version` | Print the engine version |
| `vibe-check --help` | Print help |

## Development

```bash
npm test             # node:test — unit + parser + golden + integration tests
npm run typecheck    # tsc --noEmit (JSDoc type-checked, @ts-check)
```

Install the three provider binaries to run the full suite (unit + parser tests run
without them; golden + integration tests skip when a binary is missing):

```bash
pipx install semgrep
npm install -g madge
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
