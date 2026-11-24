# AGENTS.md — vibe-check

`vibe-check` is the **open-source, local deep-scan engine** from [peek.software](https://peek.software). It turns Peek's teardown catalog into an executable audit of a codebase.

## Read first

- `docs/deep-scan-engine.md` — the complete design: vision, architecture, scoring model, rule catalog, implementation phases, and open decisions. The code now implements it; §9 tracks phase status, §5.4/§7 track what shipped. (Internal — the `docs/` folder is gitignored and not published in the public repo.)

## What it is

- A Node.js CLI (`vibe-check`) that runs **entirely on the user's machine**, against their own source code. The user never uploads code to peek.software.
- Peek only emits an **inert, declarative config** (`peek-config.json`) derived from the quiz + manifest intake. The config is data, never executed code.
- Provider registry: Semgrep (custom teardown rules) + OSV-Scanner (CVEs) + Gitleaks (secrets) + Madge (circular deps) + scc (file size) + ESLint (linter), plus built-in providers (tests, dependency hygiene, security headers, CI, Firebase/Firestore rules) and optional Checkov / Hadolint / Trivy / Bandit / gosec / PHPStan.
- Tenant isolation (TD-008) is sharpened by **automatic tenant-identity discovery** (`src/tenant/`): the Prisma schema or SQL migrations are parsed into a relation graph, the tenant aggregate root + scope columns are identified, and the rule is materialized (or reported "not statically verifiable" for layers the engine can't parse). Firestore apps get a rule/query cross-check (`src/firestore/scope.mjs`).

## Non-negotiable trust principles

1. **Zero telemetry.** The engine never calls peek.software.
2. **Offline & deterministic.** Only the OSV CVE lookup touches the network.
3. **Inert config.** Schema-validated, treated strictly as data.
4. **Open & reviewable.** No hidden actions; the repo must stay readable and forkable.

## Relationship to peek-software

- Teardown facts (`id`, `category`→pillar, `severity`, `points`, `fixSummary`) are sourced from the `peek-software` frontend catalog and vendored here as `catalog/teardowns.json` — facts only, no editorial content.
- The web app / quiz lives in a separate repo (`/var/projects/peek-software`). This repo is the engine only.

## Conventions

- ESM (`.mjs`), Node ≥ 22, zero runtime dependencies where possible (the orchestrator shells out to external binaries).
- Every custom Semgrep rule must ship with a golden test: its TD's `vulnerableCode` fires, `hardenedCode` stays silent.
- Rules are organized per `(TD × language)` — see the design doc §7.

## Branching & releases

- Trunk-based: `main` is always releasable. One short-lived branch per TD or per stack, merged via PR when CI is green (`npm run typecheck` + `npm test`).
- Semver from `package.json`: patch = fixes / FP reduction (`0.1.1`); minor = new teardown rules or new stack support (`0.2.0`).
- A release is a tag `vX.Y.Z` + GitHub release. Published tags never move.
- New TD: peek-software catalog entry → sync facts into `catalog/teardowns.json` → `rules/peek/<TD>/` + golden fixtures → config gating if needed → validation scans on dev apps.
- New stack: `src/stack.mjs` markers + manifest detection → onboarding `TOOLS` entry → CI install step → docs (README/SETUP) → tests.
