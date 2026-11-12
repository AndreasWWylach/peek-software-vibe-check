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
- [osv-scanner](https://google.github.io/osv-scanner) — dependency CVEs (core)

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
npm test             # node:test unit tests
npm run typecheck    # tsc --noEmit (JSDoc type-checked, @ts-check)
```

## Layout

```
bin/            CLI entry
src/            engine — config, scoring, providers, report
schema/         published JSON Schema contracts (config + report)
catalog/        vendored teardown facts snapshot
rules/          custom Semgrep rules — one per (TD × language), Phase 2
tests/          unit tests
```

## License

Apache-2.0 — see `LICENSE`.
