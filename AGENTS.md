# AGENTS.md — vibe-check

`vibe-check` is the **open-source, local deep-scan engine** from [peek.software](https://peek.software). It turns Peek's teardown catalog into an executable audit of a codebase.

## Read first

- `docs/deep-scan-engine.md` — the complete design: vision, architecture, scoring model, rule catalog, implementation phases, and open decisions. Treat it as the single source of truth until code exists.

## What it is

- A Node.js CLI (`vibe-check`) that runs **entirely on the user's machine**, against their own source code. The user never uploads code to peek.software.
- Peek only emits an **inert, declarative config** (`peek-config.json`) derived from the quiz + manifest intake. The config is data, never executed code.
- Provider registry: Semgrep (custom teardown rules) + OSV-Scanner (dependency CVEs), later Gitleaks + one language-native linter.

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
