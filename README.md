# vibe-check

Open-source, local deep-scan engine for [peek.software](https://peek.software). It turns Peek's teardown catalog into an executable audit of your codebase — running **entirely on your machine, against your own source code**.

> **⚠️ Early beta — under active development.** The scanner runs end-to-end and is golden-tested against real apps, but the rule catalog still covers a growing subset of the teardown catalog, and findings & scoring may still change as it is tuned against real codebases. Treat the report as a strong, specific signal to review — not a finished audit.

> **Status:** Shipped — the engine scans real repos end-to-end with twenty providers and fifteen teardown rules (all golden-tested), plus automatic tenant-identity discovery (Prisma schema + SQL migrations), a Firestore rule/query cross-check, and a PostgreSQL/Supabase row-level-security check. The full design doc is internal (not published in this repo); see **[peek.software/scan](https://peek.software/scan)** for more about the scanner.

## Trust statement

1. **Zero telemetry.** The engine never calls peek.software.
2. **Offline & deterministic.** `run` never touches the network — only the OSV CVE lookup does, plus the separate, opt-in `probe <url>` command, which talks exclusively to the URL you provide.
3. **Inert config.** `peek-config.json` is schema-validated data — never executed code.
4. **Open & reviewable.** Apache-2.0. No hidden actions.

## Prerequisites (for all supported stacks)

- Node.js ≥ 22
- [semgrep](https://semgrep.dev) — custom teardown rules (core)
- [osv-scanner](https://google.github.io/osv-scanner) **v2** — dependency CVEs (core)
- [madge](https://github.com/pahen/madge) — circular-dependency graph → architecture findings (core)
- [scc](https://github.com/boyter/scc) — file-size metrics → monolithic-file findings (core)
- [gitleaks](https://github.com/gitleaks/gitleaks) — secrets → hardcoded-secret findings (core)
- [eslint](https://eslint.org) **9** — language linter → QA hygiene findings (core)
- [checkov](https://www.checkov.io) — IaC misconfiguration + IAM wildcard scanning (optional)
- [hadolint](https://github.com/hadolint/hadolint) — Dockerfile quality & hygiene lint (optional)
- [trivy](https://trivy.dev) — filesystem vulnerability + secret scanning (optional)
- [bandit](https://bandit.readthedocs.io) — Python security SAST (optional, Python repos only)
- [gosec](https://github.com/securego/gosec) — Go security SAST (optional, Go repos only)
- [phpstan](https://phpstan.org) — PHP static analysis, hallucination checks (optional, PHP ≥ 8.1; composer-installed PHP apps)

The **tests**, **dependency-hygiene**, **security-headers**, **CSRF**, **wildcard-CORS**, **CI**, **Firebase** and **PostgreSQL/Supabase RLS** providers are built into the engine — no binary to install. The **Semgrep PHP packs** (core + Laravel/Symfony/Doctrine/WordPress) are vendored into `rules/vendored/php/` (offline, pinned SHA) and selected automatically from `composer.json`. The **PHPStan framework extensions** (phpstan-symfony, phpstan-doctrine) are likewise vendored into `rules/vendored/phpstan/` — Symfony/Pimcore/Doctrine apps need only the `phpstan` PHAR, no Composer. **Laravel** is the one exception: `larastan` is *not* vendored (it boots the app's own Illuminate), so run `composer require --dev larastan/larastan` inside the Laravel app first.

A missing binary is reported as **"skipped"** in the report — never a failure. The engine degrades gracefully.

## Usage

```bash
git clone https://github.com/AndreasWWylach/peek-software-vibe-check.git
cd peek-software-vibe-check
npm install
node bin/vibe-check.mjs run --config /path/to/peek-config.json
```

This writes `AUDIT-REPORT.md` (human), `peek-report.json` (machine) and
`FIX-PROMPTS.md` (copy-paste AI remediation prompts, one per finding group)
into the current directory. Skip the prompts with `--no-fix-prompts`;
regenerate them from an existing report with `vibe-check fix-prompts`.

### Fix it with AI

Every run also writes **`FIX-PROMPTS.md`**: one copy-paste remediation prompt
per finding group, grounded in the actual finding's evidence (file, line,
message) and its teardown's fixSummary — never generic advice. Paste each
section into any AI coding agent that can edit files (Claude Code, Cursor,
Codex, aider, OpenCode with DeepSeek). Each prompt ends with verification:
re-run the scan and confirm the finding is gone — the fix is proven by the
scanner, not claimed by the model. For Claude Code there is a bundled skill
(`skills/vibe-check/`); `AI-FIX-GUIDE.md` is the harness-neutral version of the
same workflow.

### Onboarding (installer)

One command gets the machine ready — no two-mile setup guide. Every install is
shown (command + source + checksum) before it runs, and is interruptible and
idempotent:

```bash
vibe-check doctor                 # read-only: what's installed / missing / outdated
vibe-check setup                  # interactive installer (y/n/skip per tool)
vibe-check setup --dry-run        # print every planned step, install nothing
vibe-check setup --yes            # non-interactive (accept everything)
vibe-check setup --all            # consider every tool, even those this stack does not need
vibe-check setup --skip madge     # skip a tool
```

`setup` is **stack-aware**: it detects the repo you run it in (package.json,
Python manifests, composer.json, go.mod, Dockerfiles) and auto-skips tools the
stack cannot use — a JS-only repo won't be offered phpstan, a Python repo won't
be offered eslint. Override with `--all`.

Or bootstrap everything from a shell (checks Node ≥ 22, clones the engine,
installs its dependency, puts `vibe-check` on PATH, then runs the onboarding):

```bash
curl -fsSL https://raw.githubusercontent.com/AndreasWWylach/peek-software-vibe-check/main/setup.sh -o setup.sh
less setup.sh   # review before running — transparency first
bash setup.sh
```

### CLI

| Command | Description |
| --- | --- |
| `vibe-check run --config <path>` | Run the scan against a `peek-config.json` |
| `vibe-check run --config <path> [--out <dir>]` | Run the scan against a `peek-config.json` and write reports to `<dir>` |
| `vibe-check run --config <path> --no-fix-prompts` | Run the scan without writing `FIX-PROMPTS.md` |
| `vibe-check fix-prompts --report <path>` | Re-generate `FIX-PROMPTS.md` from an existing `peek-report.json` (no re-scan, offline) |
| `vibe-check probe <url>` | Opt-in, read-only live check of a deployed site you own (bounded requests, private targets rejected) |
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

Install the twelve provider binaries to run the full suite (unit + parser tests run
without them; golden + integration tests skip when a binary is missing):

```bash
pipx install semgrep
pipx install checkov
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
# hadolint (Linux amd64):
curl -sSL -o ~/.local/bin/hadolint \
  https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64
chmod +x ~/.local/bin/hadolint
# trivy (Linux amd64):
curl -sSL -o /tmp/trivy.tar.gz \
  https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz
tar -xzf /tmp/trivy.tar.gz -C ~/.local/bin trivy
# bandit (Python):
pipx install bandit
# gosec (Linux amd64):
curl -sSL -o /tmp/gosec.tar.gz \
  https://github.com/securego/gosec/releases/download/v2.30.0/gosec_2.30.0_linux_amd64.tar.gz
tar -xzf /tmp/gosec.tar.gz -C ~/.local/bin gosec
# phpstan (PHAR, needs PHP ≥ 8.1):
curl -sSL -o ~/.local/bin/phpstan \
  https://github.com/phpstan/phpstan/releases/download/2.3.1/phpstan.phar
chmod +x ~/.local/bin/phpstan
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
rules/          custom Semgrep rules — teardown (peek/) + always-on hardening (hygiene/)
skills/         Claude Code remediation skill (vibe-check)
AI-FIX-GUIDE.md harness-neutral remediation workflow for any AI agent
examples/       sample app used by the integration test
tests/          unit, parser, golden, and integration tests
```

## Contributing

The scanner is open (Apache-2.0) precisely so it can be sharpened in the open — contributions that make the scan quieter or catch one more real bug are the most valuable, and very welcome.

- **Rules** — every teardown rule lives in `rules/peek/<TD-id>/` and must ship with a golden test under `tests/golden/fixtures/<td-id>/`: the TD's `vulnerableCode` must fire and its `hardenedCode` must stay silent.
- **Providers** — one module per analysis capability in `src/providers/`; a missing binary degrades gracefully ("skipped"), never fails.
- **Tenant discovery** — data-layer parsers live in `src/tenant/parsers/` and emit a shared `TenantDescriptor` (see the internal design doc §5.4).

Start from an issue or open a small, focused PR. `npm test` (and `npm run typecheck`) is the bar; the design lives in the internal design doc (`docs/`, not published), and `AGENTS.md` is the quick start.

## License

Apache-2.0 — see `LICENSE`.
