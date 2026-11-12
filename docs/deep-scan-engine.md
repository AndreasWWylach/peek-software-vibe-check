# peek.software — Deep Scan Engine (Working Draft)

> **Status:** DRAFT — vision + architecture, not yet implemented.
> **Last updated:** 2026-11-11
> **Scope:** the open-source, local "post-diagnosis" scanner that turns Peek's teardown catalog into an executable audit.

---

## 1. Vision

Peek's quiz is **self-reported** — it asks whether a team does the right thing, calibrated by a manifest intake. The deep scan engine is the **objective** counterpart: it runs in the user's own dev environment, against the user's own source code, and verifies what the quiz only asks about.

The key architectural inversion:

- **The user never uploads source code to peek.software.** Nothing sensitive leaves their machine.
- **Peek only emits an inert, declarative config** (`peek-config.json`) generated from the quiz answers + manifest intake.
- **The scanner itself is open-source** (public GitHub repo), fully readable — no hidden actions, no telemetry, no phoning home.

This is a reputation play as much as a technical one: a security product whose scanner is open and auditable builds the exact trust that "upload your code to us" destroys.

LastMile is not cannibalized. The engine **finds** issues; LastMile **fixes** them. The report's final section is the LastMile hand-off.

### The model

```
┌─ Peek (web) ─────────────────────────────────────────┐
│ quiz answers + manifest intake                       │
│   │                                                  │
│   ▼                                                  │
│ config generator  ──▶  peek-config.json (download)   │
└──────────────────────────────────────────────────────┘
                            │  inert, declarative, no code
                            ▼
user machine:
   git clone github.com/<owner>/<repo>       (public, readable)
   <bin> run --config peek-config.json       (local only)
   → AUDIT-REPORT.md + peek-report.json
```

---

## 2. Design decisions (the ones this hinges on)

### 2.1 The generated artifact is inert data, never a script

The config is **declarative JSON** (which rules, which parameters, which weights). It is *not* an executable shell script:

- A generated script is a supply-chain vector and contradicts the "no funny actions" promise.
- The only executable code the user runs is the **pinned, reviewable** engine from the public repo.
- Setup steps ("install Semgrep + OSV-Scanner, clone the repo, run one command") are **documented**, not executed from a downloaded blob.

### 2.2 The rule catalog is the teardown catalog, stripped of editorial content

Each executable rule maps **1:1 to a real `TD-###`** and carries only the facts:

| Fact | Source |
|---|---|
| `id` | `TD-###` |
| `category` → pillar | `TeardownCategoryEnum` |
| `severity` | `SeverityEnum` |
| `points` | rule metadata |
| `message` | short "what's wrong" |
| `fixSummary` | from the TD's `fixSummary` / `hardenedCode` |

The editorial layer — story, `flaw`, `impact`, before/after code — **stays on `peek.software/teardowns/TD-###`**. The report deep-links each finding to the teardown page via `teardownPath(id)`.

Consequence: open-sourcing the scanner does **not** open-source the editorial content. The moat was never the Semgrep patterns — it is the teardown writing, the quiz funnel, and LastMile's services.

### 2.3 Facet-gating is already solved — reuse it

The quiz schema already has `requires: ['server','llm','multitenant','auth',…]` (see `FACETS` in `frontend/src/data/quiz/schemas.ts`), and the backend already derives facets from the manifest (`detectFrameworks` / `deriveFacets`).

Therefore "customized to the user's app" falls out for free: **activate a TD rule iff the app's derived facets satisfy the TD's `requires`.**

- A Next.js app with `llm` + `auth` facets → TD-002 (unbounded tokens) and TD-008 (IDOR) enabled.
- A static landing page → neither.

---

## 3. Customization levels (staged)

1. **Facet-gated rule subset** (objective, from manifest intake) — build first.
2. **Quiz-weighted emphasis** — user hotspots influence scoring/report ordering; report shows the calibration moment: *"you answered Q2.2 'we cap tokens' → scan found TD-002."* This is where self-report becomes verifiable.
3. **Rule parameters** — tenant column name, LLM SDK (openai/anthropic), ORM flavor. Highest value, hardest (rules must be parameterizable); defer to v2.

---

## 4. Trust principles (hard requirements)

1. **Deterministic & offline.** Zero calls to `peek.software`, zero telemetry. Only OSV (public CVE API) touches the network.
2. **No code execution from config.** The engine schema-validates the config and treats it strictly as data.
3. **Pinned releases.** Install path references a tagged release / commit hash, so "clone and run" is verifiable.
4. **Schema-validated config.** Malformed config → fail loudly, never guess.

---

## 5. Architecture

### 5.1 Repository layout (engine — public GitHub repo, standalone)

```
<repo>/                        # peek-software-vibe-check — public
├── bin/                       # CLI entry
├── src/
│   ├── run.mjs                # orchestrator: Semgrep → OSV → hygiene → report
│   ├── config.mjs             # config loader + JSON Schema validation (ajv)
│   ├── scoring.mjs            # pillar weights, severity→points, tier thresholds
│   └── report.mjs             # JSON → Markdown renderer
├── schema/
│   ├── peek-config.schema.json   # config contract (JSON Schema, versioned)
│   └── peek-report.schema.json   # report contract (JSON Schema, versioned)
├── rules/
│   └── peek/<TD-id>/<lang>.yaml  # custom Semgrep rules — one per (TD × language)
├── catalog/
│   └── teardowns.json         # VENDORED facts snapshot (id/pillar/severity/points/fixSummary/languages)
├── tests/
│   └── golden/                # vulnerableCode → fires; hardenedCode → silent
├── package.json
└── README.md                  # setup steps, trust statement
```

### 5.2 Rule catalog ↔ teardown sync (single source of truth)

The frontend's `frontend/src/data/teardowns/catalogs/v1/en/*.json` is the **source of truth** for TD facts. The engine repo **vendors a generated `catalog/teardowns.json`** — a facts-only snapshot (no editorial fields) regenerated by Peek on deploy.

- Keeps the public repo self-contained and readable.
- Sync is one-way (Peek → engine) and automated.
- The editorial fields (`prompt`, `flaw`, `impact`, `vulnerableCode`, `hardenedCode` narrative) are excluded from the snapshot.

### 5.3 Config generator (peek.software side)

A new backend endpoint (e.g. `POST /api/generate-scan-config`) that takes quiz answers + manifest analysis and emits `peek-config.json`:

```jsonc
{
  "$schema": "./schema/peek-config.schema.json",
  "version": 1,
  "engine": ">=0.1.0",
  "targets": ["src/", "backend/"],          // derived from manifest
  "languages": ["typescript", "python"],
  "enabledRules": ["TD-002", "TD-008", ...], // facet-gated subset
  "ruleParams": { "tenantColumn": null },     // v2
  "scoring": { "weights": { "security": 1.0, "runtime": 1.0, "architecture": 1.0, "qa": 1.0 } },
  "quiz": {                                   // for the calibration overlay (v2)
    "totalScore": 142,
    "hotspots": ["Q2.2", "Q3.4"],
    "pillarBreakdown": { "security": 34, "runtime": 51, "architecture": 30, "qa": 27 }
  }
}
```

### 5.4 Engine pipeline

```
config ──▶ validate
        ──▶ Semgrep (rules/peek/*.yaml filtered by enabledRules) ──▶ findings
        ──▶ OSV (lockfiles / manifests)                          ──▶ dependency findings
        ──▶ hygiene (dead code, unused exports — QA pillar)      ──▶ hygiene findings
        ──▶ map findings → pillar → points
        ──▶ score (reuse quiz constants) + tier
        ──▶ render AUDIT-REPORT.md + peek-report.json
```

### 5.5 Ecosystem & language matrix

The engine is **ecosystem-agnostic by construction** — it shells out to Semgrep (30+ languages) and OSV (all ecosystems). What changes per language is the **rule catalog**, not the engine.

- A rule is **one per `(TD × language)`**, not one per TD. Command injection (TD-042) has a JS pattern, a Python pattern, a PHP pattern, a Go pattern…
- Some TDs are **language-specific**: TD-045 (`ts-ignore`) is TypeScript-only, TD-046 (bare `except: pass`) is Python-only, TD-036 (foreach reference leak) is PHP-only, TD-006 (buffer overflow) is C-only. They have no variant for other languages.
- Rule enablement is the **intersection of two dimensions**: `TD.requires ⊆ facets` (app anatomy) **AND** `TD has a pattern for a detected language` (app stack).

**Language detection sources** (already present in the codebase):

| Source | Map |
|---|---|
| Manifest ecosystem | `npm → JS/TS`, `pip → Python`, `php → PHP`, `go → Go`, `rust → Rust`, `ruby → Ruby`, `jvm → Java/Kotlin/Scala` |
| Teardown `stack` field | e.g. `["typescript", "nextjs", "node"]` |
| Repo scan (quick path, no quiz) | detect lockfiles directly (`package-lock.json`, `requirements.txt`, `composer.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `pom.xml`…) |

The pillar / scoring / report layers are **language-neutral** — no changes there.

**Semgrep taint-mode caveat:** injection rules (TD-004/033 SQL, TD-042 command injection) ideally use `mode: taint`, which Semgrep supports in fewer languages than its pattern mode. This is the real constraint on *which TDs* are coverable in *which languages*, and it is tracked per rule.

### 5.6 Dependency scanning is already ecosystem-native

The dependency/CVE half needs **zero new work** to go multi-ecosystem:

- The backend manifest layer already maps `ECOSYSTEM_BY_BASENAME` (npm · pip · php) and recognizes **go/rust/ruby/jvm filenames as deferred** (`DEFERRED_ECOSYSTEM_BY_BASENAME` in `backend/services/manifest/parsers/index.js`).
- `toOsvEcosystem` already maps `npm → npm`, `pip → PyPI`, `php → Packagist`.
- For the **local engine**, prefer `osv-scanner` directly: it natively walks all lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `composer.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `pom.xml`, `build.gradle`) — current *and future* ecosystems covered by one binary, no custom parser work.
- Adding Go/Rust/Ruby/JVM on the **peek.software side** = one parser per ecosystem + one line in `toOsvEcosystem`; the deferred-filename scaffolding already exists.

### 5.7 Tool provider registry (extending beyond Semgrep + OSV)

The engine is a **provider registry**, not a fixed pipeline. Every analysis capability is a pluggable provider that emits findings in the shared `peek-report.json` shape. Two gates per provider:

- `available(tools)` — is the binary installed? Missing → report says "skipped; install X to enable", never fail.
- `applicable(config)` — does the provider fit this app (facets + languages)?

```text
findings = aggregate(provider.run() for provider in enabled if provider.available && provider.applicable)
```

Two cross-cutting requirements:

- **Finding dedup** — Semgrep *and* Bandit will both flag `subprocess`; same `teardownId` + file/line collapse to one finding (max severity, union of fix hints).
- **Precision over volume** — deeper tools add confidence + coverage, not just more noise.

**Adoption is staged — pick a few, prove the score, then expand.** Not all of these at once.

| Tier | Tool | Adds | Gate |
|---|---|---|---|
| **Core (v1)** | Semgrep | custom TD patterns + taint | always |
| | OSV-Scanner | dependency CVEs | always |
| | **Gitleaks** | secrets (TD-016/026) — offline, high precision | security facet |
| | **one language-native linter** (Ruff / ESLint / golangci-lint…) | QA pillar + cheap extra coverage | detected language |
| **Opt-in "deep mode"** | CodeQL | dataflow-proven findings (TD-033/041/042) | needs build; user opts in |
| | govulncheck | reachability-aware Go vulns | go facet |
| | Trivy | container + IaC misconfig | runtime facet, ships containers |
| | hadolint | Dockerfile lint | runtime facet |
| **Later (if helpful)** | Bandit / Brakeman / gosec / Psalm / SpotBugs+FindSecBugs | ecosystem-native SAST per language | detected language |
| | Garak / Promptfoo | LLM probing (TD-014) — needs live endpoint | llm facet, opt-in |
| | dependency-cruiser / ArchUnit / deptrac / Madge | architecture graph (TD-021) | architecture facet |
| | radon / scc / tokei | complexity + size metrics (TD-019) | qa / architecture facet |

### 5.8 Setup & onboarding (the installer)

One command, two personalities — beginner and advanced meet in the middle.

- **Beginner path** — guided, friendly, `y/n/skip` per missing tool; prints every command before running it; ends with a ✓/✗/⟳ summary table.
- **Advanced path** — the same script with flags: `--check` (doctor, read-only), `--yes` (non-interactive), `--skip <tool>`, `--dry-run`, `--no-color`. CI-safe.

**Entry points:**

| Command | What it does |
|---|---|
| `vibe-check doctor` | read-only prerequisite check (cross-platform, runs on Node) |
| `vibe-check setup` | interactive installer with `y/n/skip` |
| `setup.sh` | thin macOS/Linux wrapper: bootstraps Node, then delegates to `vibe-check setup` |

**Script contract (non-negotiables):**

1. Detect OS + package manager on macOS/Linux (brew / apt / dnf / apk). Windows is explicitly out of scope.
2. Check each prerequisite: `node`, `semgrep`, `osv-scanner`, `gitleaks`, language linter.
3. For each missing tool, show the exact command, then ask `[Y]es / [n]o / [s]kip / [a]ll remaining`.
4. Idempotent — safe to re-run any time.
5. Install only from official sources; verify checksums for downloaded binaries.
6. Skipping is always safe — the engine degrades gracefully (provider `available()` gate).

**Bootstrap order:** Node first (the engine itself) → Semgrep + OSV-Scanner (core) → Gitleaks (security facet) + language linter. "Deep mode" tools (CodeQL, Trivy, Garak…) are *mentioned*, never auto-installed.

**On `curl | sh`:** offered as a convenience only, with a "view source first" note; the recommended path is `git clone` of a pinned release — consistent with the trust principles.

---

## 6. Scoring model (shared language with the quiz)

Reuse the quiz's exact constants — already proven coherent:

| Constant | Value | Source |
|---|---|---|
| Total risk score | 0–350 | `MAX_TOTAL_SCORE` |
| Pillar maxes | security 90 · runtime 90 · architecture 90 · qa 80 | `PILLAR_MAX_SCORES` |
| Pillar labels | as quiz | `PILLAR_LABELS` |
| Tier thresholds | green ≤17% · amber ≤46% · red >46% | `TIER_THRESHOLDS` |

- Direction: **higher = riskier**, matching the quiz.
- Each finding contributes `points` to its pillar; pillar scores are capped at the pillar max; total capped at 350.
- Criticals impose a **hard floor** (e.g. any critical → tier cannot be green), so "readiness" stays truthful.
- **Not statically verifiable** TDs are reported as "see guide rule X", not silently scored as zero.

---

## 7. Rule catalog

### 7.1 v1 — high-precision set (8 rules)

A rule is a **`(TD × language)` matrix cell**, not one pattern. v1 coverage order: **JS/TS → Python → PHP**. A `—` means the TD has no variant in that language (inapplicable or deferred).

| TD | Concept | JS/TS | Python | PHP | Pillar |
|---|---|---|---|---|---|
| TD-002 | LLM call without token cap | OpenAI SDK | openai | — | runtime |
| TD-008 | IDOR — lookup by raw `id`, no tenant/user scope | Prisma | SQLAlchemy / Django | Eloquent | security |
| TD-016 | hardcoded API key / token | ✓ | ✓ | ✓ | security |
| TD-032 | unauthenticated request handler | Express / Next | Flask / FastAPI | Laravel / Symfony | security |
| TD-033 | string-concatenated SQL | template strings | f-string / `%` | concat | security |
| TD-042 | command injection | `exec` / `spawn` | `subprocess` / `os.system` | `shell_exec` / `system` | security |
| TD-045 | `ts-ignore` / `any` escape hatch | TS only | — | — | architecture |
| TD-046 | bare `except: pass` | — | Python only | — | runtime |

### 7.2 Detectability split (full catalog, 40 TDs)

- **~25 statically detectable** via Semgrep: TD-002, 004, 006, 007, 008, 009, 016, 018, 019, 020, 022, 026, 030, 031, 032, 033, 034, 035, 036, 037, 038, 039, 040, 041, 042, 043, 044, 045, 046…
- **~15 not statically detectable** (behavioral/architectural): TD-014 (prompt injection), 017 (hallucinated tests), 021 (pattern fragmentation), 027 (runaway agent), 028 (contract regression), 047/048/049 (logic/race)… → reported as "see Environment guide rules 16–22", not scored.
- **A third case — "detectable, but not in your language":** a TD may have a Semgrep variant for one language but not another (e.g. TD-046 only exists for Python). The report distinguishes "not detectable at all" from "not covered for your stack", so coverage gaps are honest, never silent zeros.

### 7.3 Golden tests (the credibility gate)

Every rule must pass a **golden test harness**:

- `vulnerableCode` from the TD → rule **fires**.
- `hardenedCode` from the TD → rule **silent** (no false positive).

No rule ships until both assertions pass. This is what prevents the scanner from being dismissed as noisy.

### 7.4 Best tool per TD (which provider flags what)

| TD | Preferred provider (over Semgrep) |
|---|---|
| TD-016 / TD-026 (secrets) | Gitleaks |
| TD-037 / TD-038 / TD-039 (Python RCE/SSTI) | Bandit |
| TD-033 / TD-042 (SQLi / command injection) | taint — CodeQL · Psalm · gosec · Bandit |
| TD-041 (prototype pollution) | CodeQL (JS) |
| TD-014 (prompt injection) | Garak / Promptfoo (dynamic) |
| TD-019 (monolithic file) | radon / scc / tokei (metrics) |
| TD-021 (pattern fragmentation) | **Madge** (adopted — circular deps) |
| TD-044 (floating promise / unhandled rejection) | **deferred to type-aware linter** — ESLint `no-floating-promises` |
| Runtime infra (Dockerfile, root user, healthcheck) | Trivy config / hadolint |
| Go reachable vulns | govulncheck |

> **TD-044 deferred to the linter (why):** a pattern-mode Semgrep rule can't
distinguish a call that returns a Promise (e.g. `db.insertEvent(...)`) from a
harmless fire-and-forget call, so it would be noisy — violating
precision-over-volume. The type-aware ESLint `no-floating-promises` rule sees
real types and flags only genuinely-unhandled promises.

---

## 8. Report output

`AUDIT-REPORT.md` (human) + `peek-report.json` (machine / agent-consumable).

```markdown
# Local Deep Code Audit Report
**Date:** 2026-11-11
**Engine:** vibe-check 0.1.0 (public, commit <hash>)

## Overall Risk Score
- 142 / 350 — 🟡 Needs Hardening

## Pillar Breakdown
| Pillar | Risk Score | Max |
| ... |

## Findings
### security
- **TD-008** (`src/app/api/users/route.ts:41`): lookup by raw id without tenant scope
  → see https://peek.software/teardowns/TD-008

## Not Statically Verifiable
- TD-014 (prompt injection) — see guide rule 16

## Next Steps
- Get It Fixed by Last Mile → ...
```

`peek-report.json` findings carry `{ id, file, line, severity, pillar, teardownId, message, fixSummary }` so an agent can be instructed: *"Read `peek-report.json` and fix every flagged teardown without breaking tests."*

---

## 9. Implementation plan (draft)

**Phase 0 — contract.** Define `peek-report.json` schema + config schema + the facts snapshot format. Freeze scoring constants (import from quiz).

**Phase 1 — engine skeleton (public repo).** CLI, config loader, **provider registry** (Semgrep + OSV-Scanner as the first two providers), finding dedup, pillar mapping, Markdown renderer, offline/deterministic guarantees. Ship with 0 custom rules.

**Phase 2 — golden rulepack.** Write the 8 v1 rules (JS/TS first, then Python, then PHP) + golden test harness against the TD `vulnerableCode`/`hardenedCode` pairs — one fixture set per language. Vendor `catalog/teardowns.json` including the `languages` matrix.

**Phase 3 — config generator (peek.software).** `POST /api/generate-scan-config` + quiz-results "Run the deep scan" section (download config + setup steps).

**Phase 4 — calibration overlay (v2).** Config carries quiz scores; report shows self-report vs. scan.

**Phase 5 — parameterized rules + full detectable catalog.**

---

## 10. Open decisions

- [x] **Naming & repo** — `peek-software-vibe-check` (repo/folder) · `vibe-check` (CLI + npm). Standalone repo under the personal GitHub account.
- [x] **OSV transport** — shell out to the local `osv-scanner` binary (multi-ecosystem lockfile parsing for free, incl. go/rust/ruby/jvm; `osv.js` stays backend-only for the quiz intake).
- [x] **Config schema format** — JSON Schema (language-agnostic, self-describing published contract; validated with `ajv` in the engine; Zod stays an internal Peek-backend concern).
- [x] **Hygiene tool** — no dedicated dead-code tool in v1 (Knip is JS-only and adds uncertainty). The QA pillar gets its signal from the language linter + Semgrep rules (TD-022 for QA; TD-045 = architecture, TD-046 = runtime). Revisit after real reports.
- [x] **Snapshot sync mechanism** — a simple script in peek-software that regenerates `catalog/teardowns.json` from the frontend catalog (run manually / on deploy). Full CI pipeline later.
- [x] **Publish timing** — no fixed date. Release when the analyzer is ready, usable, helpful, tested enough, and does the job (golden tests green + a self-scan of a real repo looks sane). A reputation project — quality over timeline.
- [x] **Language coverage order** — JS/TS first (richest catalog + AI-code sweet spot), then Python, then PHP. Go/Rust/Ruby/JVM rule variants land later, after the deferred parsers flip on.
- [x] **Taint-mode scope** — pattern-mode only in v1 for all 8 rules. Fallback: if golden tests show TD-033/042 are too noisy in pattern-mode, tighten the patterns or defer those two to v2 — the golden harness is the arbiter, not a guess.
- [x] **Provider selection (v1)** — Semgrep + OSV-Scanner only for the first cut; add Gitleaks + one language-native linter once the first golden rules land. Prove the score isn't noise before adding breadth.
- [x] **Installer surface** — `vibe-check setup` (cross-platform Node CLI) + a `setup.sh` wrapper. **No Windows support** — macOS & Linux only; no `.ps1`, no winget/scoop/choco.
- [x] **License** — **Apache-2.0** (permissive + explicit patent grant + contributor protections; the standard choice for open security tooling). The actual `LICENSE` file lands with the scaffold.
