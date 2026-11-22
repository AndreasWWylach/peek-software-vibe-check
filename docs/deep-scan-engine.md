# peek.software — Deep Scan Engine (Working Draft)

> **Status:** IMPLEMENTED — shipped and scanning real repos; §1–§8 are the current design, §9–§10 are historical (phases done / decisions closed).
> **Last updated:** 2026-11-15
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
3. **Rule parameters** — tenant column name, LLM SDK (openai/anthropic), ORM flavor. Highest value, hardest (rules must be parameterizable); defer to v2. The tenant column is **auto-detected** from the scanned schema/models (see §5.4); the config may still carry an explicit `tenantColumn` as a manual override.

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
│   ├── run.mjs                # orchestrator: providers → dedup → score → report
│   ├── config.mjs             # config loader + JSON Schema validation (ajv)
│   ├── scoring.mjs            # pillar weights, severity→points, tier thresholds
│   ├── report.mjs             # JSON → Markdown renderer (verdict, summaries, findings)
│   ├── findings.mjs           # dedup + deterministic sort
│   ├── calibration.mjs        # self-report vs. scan overlay (quiz data)
│   ├── catalog.mjs            # vendored teardown facts lookup
│   ├── ignore.mjs             # shared path filters (junk dirs, env, test files)
│   ├── discover.mjs           # source-directory discovery (auto-include targets)
│   ├── stack.mjs              # scan-time stack markers (Firebase/Firestore/Prisma/SQL/…)
│   ├── tenant/                # tenant-identity discovery (TD-008 sharpening)
│   │   ├── descriptor.mjs     #   language/ORM-neutral tenant contract
│   │   ├── discover.mjs       #   dispatch (Prisma → SQL → not-verifiable)
│   │   └── parsers/           #   prisma.mjs (relation graph) · sql.mjs (FK graph)
│   ├── firestore/             # Firestore rules parsing + query cross-check
│   │   └── scope.mjs          #   match-path → required fields → query mismatch
│   ├── version.mjs            # engine name/version/commit
│   ├── onboarding.mjs         # `vibe-check setup` installer logic
│   └── providers/             # one module per analysis capability
│       ├── semgrep.mjs        # custom teardown rules (rules/peek/*) + always-on hygiene rules (rules/hygiene/*)
│       ├── osv.mjs            # dependency CVEs (osv-scanner)
│       ├── madge.mjs          # circular deps → TD-021
│       ├── scc.mjs            # file size → TD-019
│       ├── gitleaks.mjs       # secrets → TD-016
│       ├── deps.mjs           # dependency hygiene: missing lockfile (scored) + floating versions (advisory)
│       ├── headers.mjs        # security-header absence for server frameworks (advisory)
│       ├── ci.mjs             # CI pipeline: no-pipeline / no-tests / no-coverage (advisory)
│       ├── checkov.mjs        # IaC misconfiguration + IAM wildcards (checkov, optional)
│       ├── hadolint.mjs       # Dockerfile quality & hygiene lint (hadolint, optional)
│       ├── trivy.mjs          # filesystem vuln + secret scanning (trivy, optional)
│       ├── bandit.mjs         # Python security SAST (bandit, optional, Python repos)
│       ├── gosec.mjs          # Go security SAST (gosec, optional, Go repos)
│       └── phpstan.mjs        # PHP static analysis / hallucination checks (phpstan, optional)
│       ├── eslint.mjs         # language-linter hygiene (QA)
│       ├── tests.mjs          # test presence + assertion heuristic (QA)
│       ├── firebase.mjs       # Firestore/Storage security-rules boundary (QA → security)
│       └── rls.mjs            # PostgreSQL/Supabase row-level-security boundary (security)
├── schema/
│   ├── peek-config.schema.json   # config contract (JSON Schema, versioned)
│   └── peek-report.schema.json   # report contract (JSON Schema, versioned)
├── rules/
│   ├── peek/<TD-id>/<lang>.yaml  # custom Semgrep rules — one per (TD × language)
│   ├── hygiene/*.yaml            # always-on LastMile hardening rules (XSS / open redirect / eval)
│   ├── vendored/php/…            # vendored Semgrep PHP packs (lang/laravel/symfony/doctrine/wordpress) + manifest.json
│   └── vendored/phpstan/…        # vendored PHPStan extensions (phpstan-symfony, phpstan-doctrine) + manifest.json
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
  "exclude": ["vendor/", "examples/"],       // optional — paths skipped (targets + auto-include)
  "languages": ["typescript", "python"],
  "enabledRules": ["TD-002", "TD-008", ...], // facet-gated subset
  "ruleParams": { "tenantColumn": null },     // optional manual override — the engine auto-detects it
  "scoring": { "weights": { "security": 1.0, "runtime": 1.0, "architecture": 1.0, "qa": 1.0 } },
  "quiz": {                                   // for the calibration overlay (v2)
    "totalScore": 142,
    "hotspots": ["Q2.2", "Q3.4"],
    "pillarBreakdown": { "security": 34, "runtime": 51, "architecture": 30, "qa": 27 }
  }
}
```

**Two generation modes (decided 2026-11-12):** the manifest intake alone is
sufficient to generate a runnable config — `enabledRules` is facet-gated from the
manifest, and the quiz only feeds the optional `quiz` block. So the quiz is
**optional**: the intake offers "generate config & run now" (scan-only) alongside
"continue with the quiz" (calibrated self-report overlay). The engine already
treats `quiz` as optional — no engine change required; the generator just emits
the `quiz` block only when answers exist.

`exclude` is an optional list of repo-relative path prefixes that are skipped by
every provider (both the explicit `targets` and the auto-included source dirs).
It is the escape hatch for vendored/generated/fixture code that is not part of
the app under audit.

### 5.4 Engine pipeline

```
config ──▶ validate
        ──▶ providers (registry §5.7):
        │     Semgrep (rules/peek/*.yaml + always-on rules/hygiene/*.yaml) ──▶ teardown + hygiene findings
        │     OSV-Scanner (lockfiles)                              ──▶ dependency findings
        │     Madge (circular deps) · scc (file size)               ──▶ teardown findings
        │     Gitleaks (secrets)                                    ──▶ teardown findings
        │     deps (missing lockfile · floating versions)           ──▶ hygiene findings
        │     headers (security-header absence) · ci (pipeline)      ──▶ hygiene findings
        │     checkov (IaC misconfig · IAM wildcards)               ──▶ hygiene findings
        │     hadolint (Dockerfile lint)                            ──▶ hygiene findings
        │     trivy (vuln · secrets)                                ──▶ dependency + hygiene findings
        │     bandit (Python SAST) · gosec (Go SAST)                ──▶ teardown + hygiene findings
        │     phpstan (PHP static analysis, vendor/ gated)          ──▶ QA advisory findings
        │     ESLint (linter) · tests (presence/assertions)         ──▶ hygiene + QA findings
        │     Firebase/Firestore (security rules)                    ──▶ teardown findings
        │     PostgreSQL/Supabase (row-level security)               ──▶ teardown findings
        ──▶ dedup (same teardownId + file/line collapses)
        ──▶ map findings → pillar → points (dependency CVEs + test-file findings excluded from score)
        ──▶ score (reuse quiz constants) + tier
        ──▶ render AUDIT-REPORT.md + peek-report.json
```

TD-008 tenant sharpening is automatic. The engine detects the tenant identity
from the app's data layer (`src/tenant/`), never from the intake:

- **Prisma** — `schema.prisma` is parsed into a model relation graph; the tenant
  is the **aggregate root** (a model referenced by ≥2 others and referencing
  none — e.g. `Client` referenced via `clientId`). The materialized rule then
  checks only the tenant-scoped models with exactly the discovered column(s),
  so a deliberately global model (a shared catalog) is never flagged.
- **SQL migrations** — `CREATE TABLE … FOREIGN KEY … REFERENCES` (table- and
  column-level) builds the same relation graph. The tenant table + column are
  detected, but raw-SQL query scoping is not yet auto-checkable, so it is
  reported as **"not statically verifiable"** with the detected tenant named in
  the guidance.
- **Other data layers** (TypeORM, Mongoose, Sequelize, Drizzle, Pimcore data
  objects) — reported as "no parseable data layer" with guidance.
  `ruleParams.tenantColumn` is the manual override for these (and for any layer
  where auto-detection is wrong).

**Firestore rule/query cross-check** — for Firebase apps, `firestore.rules` is
parsed (`src/firestore/scope.mjs`) and Firestore queries in source are checked
against the rule-required fields (e.g. `ownerUid`); a query that doesn't
constrain by them is a `rule-query-mismatch` finding (TD-008). The cross-check
needs the rules and the client queries in one repo — when they're split across
repos (as in a monorepo where rules live elsewhere), it is skipped honestly.

**PostgreSQL/Supabase RLS check** — for Postgres apps the table-level boundary
is row-level security, not an ORM `where` clause. `src/providers/rls.mjs` parses
the SQL migrations and flags every `CREATE TABLE` whose RLS is never enabled
(`ALTER TABLE … ENABLE ROW LEVEL SECURITY`, `FORCE` also counts, `DISABLE` after
`ENABLE` wins). A table with `CREATE POLICY` statements but no `ENABLE` is the
silent killer — the policies are inert — and is reported as critical. The check
only fires when the repo proves it is Postgres: a `supabase`/`postgres` stack
marker (SDK dependency or `supabase/config.toml`) or Postgres-only DDL in the
migrations, so a MySQL-only repo can never trip it.

**Scan-time stack detection** is automatic too: the engine reads `firebase.json`,
`package.json` dependencies, and `*.rules` files to know what the app is built
on — never asked. `firebase.json`, the root `package.json`, and root-level
`firestore.rules` / `storage.rules` are read directly from the repo root,
independent of the config `targets` (which are only a hint for source scanning),
so Firebase/Firestore is detected even when the manifest intake didn't list the
repo root. Framework-specific rules (Firestore/Storage security rules, and later
Prisma/Express) are gated on those markers, and the report opens with an App
Stack summary. No per-service intake questions. Test and fixture files never
define the stack — a fixture string that calls the Firestore SDK must not make
the engine think the repo ships a Firebase app.

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
| **Ecosystem SAST** | Bandit (Python) · gosec (Go) | per-language dataflow/taint (TD-016/033/042) | detected language |
| **Later (if helpful)** | Brakeman / SpotBugs+FindSecBugs | ecosystem-native SAST for other languages | detected language |
| | Garak / Promptfoo | LLM probing (TD-014) — needs live endpoint | llm facet, opt-in |
| | dependency-cruiser / ArchUnit / deptrac / Madge | architecture graph (TD-021) | architecture facet |
| | radon / scc / tokei | complexity + size metrics (TD-019) | qa / architecture facet |

A pure-Node **`tests` provider** (no binary to install) is also in the core tier:
it reports whether the repo has any test files, and flags test files with no
assertion calls as a TD-017 ("hallucinated tests") heuristic — see §8.1.

A pure-Node **`firebase` provider** likewise needs no binary: when the stack scan
detects Firebase/Firestore it checks the security-rules boundary — missing
`firestore.rules` (escalated to critical when the client SDK accesses Firestore
directly), open `if true` rules, rules that don't require `request.auth`, and a
low-severity heuristic flagging Cloud Function `onCall`/`onRequest` handlers with
no visible auth check.

A pure-Node **`rls` provider** (no binary) gives Supabase/Postgres the same
boundary check at the database layer: SQL migrations are parsed and every table
whose row-level security is off is a TD-008 finding — critical when the Supabase
JS client is a dependency (the browser can reach the database directly) or when
policies exist but `ENABLE ROW LEVEL SECURITY` never ran, high otherwise.

A pure-Node **`deps` provider** (no binary) reads the repo's package manifests
(`package.json`, `composer.json`, `requirements.txt`, `Gemfile`, `Pipfile`,
`pyproject.toml`, `Cargo.toml`, `go.mod`) and flags two facts: a manifest with no
lockfile (scored, medium — builds aren't reproducible) and dependency
declarations with floating versions (`*`, `latest`, `dev-*`, unbounded `>=`/`>` —
advisory, low; caret/tilde ranges are accepted as semver-bounded, and Composer
platform requirements `php`/`ext-*`/`lib-*` are skipped).

A pure-Node **`headers` provider** (no binary) detects a web-server framework
(Express/Next/Koa/Fastify/NestJS, Flask/FastAPI/Django/Starlette) and flags the
absence of security-header configuration (CSP/HSTS/X-Frame-Options/`helmet`/
`Talisman`) as an **advisory** — absence of evidence is a signal, not a defect,
since headers may be set at a reverse proxy.

A pure-Node **`ci` provider** (no binary) reads the committed CI configs
(`.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile`, …) and flags
no-pipeline, no-tests, or no-coverage-gate as **advisories**.

A **`checkov` provider** (optional, `pipx install checkov`) scans IaC files
(Dockerfile/compose, Terraform, CloudFormation/K8s by content) for
misconfiguration — including the IAM `*` wildcard smells (`CKV_AWS_109/110/111`,
scored high). Best-practice MEDIUM/LOW checks are advisories. It runs targeted
(`--file`/`--directory`), skips checkov's secrets framework (gitleaks owns
secrets), and handles checkov 3.x's array-shaped JSON with null severity via a
curated fallback map. Terrascan is a documented alternative (Go binary, Rego)
but not wired — the registry makes adding it later a ~30-line provider.

A **`hadolint` provider** (optional, single binary) lints Dockerfiles for quality
and hygiene (pin image tags, pin apt/npm versions, JSON CMD, pipefail). It is
the Dockerfile-*quality* counterpart to checkov's Dockerfile-*security* checks;
both report as **advisories** (runtime infra posture, not scored).

A **`trivy` provider** (optional, single binary) scans the filesystem with
`--scanners vuln,secret` — vulnerabilities (merged into the dependency/CVE table
with osv-scanner) and secrets (advisory; gitleaks remains the scoring secret
engine). Its IaC misconfiguration scanner is skipped (checkov owns that).

**Vendored Semgrep PHP packs** (`rules/vendored/php/`): the community PHP rulesets
(`php/lang` core + Laravel/Symfony/Doctrine/WordPress) are pinned (SHA) and
committed — offline, never downloaded from the Registry at scan time — and
selected at scan time from the detected stack: `lang` always; the framework pack
when the `composer.json` marker matches (Pimcore → Symfony + Doctrine). Hits
that are **taint-proven** SQLi/command injection map to TD-033/TD-042 and score;
everything else is a hygiene advisory. `scripts/vendor-php-rules.mjs` refreshes
them, and `vibe-check doctor` warns when they are older than 90 days.

**Cross-tool corroboration** (`src/findings.mjs` → `corroborateFindings`): when
two engines independently flag the same issue — trivy + gitleaks on the same
secret (by file:line), or trivy + osv-scanner on the same package (by
package+ecosystem, CVE ids unioned) — the engine collapses them into one finding
annotated `corroboratedBy`, rendered as *"confirmed by trivy"*. Agreement is a
confidence signal, not noise. Note trivy's secret engine embeds gitleaks' rules,
so its secret overlap is weaker confirmation than its independent vulnerability
DB (trivy vs OSV), which is the genuinely independent check.

A **`bandit` provider** (optional, `pipx install bandit`) gives Python the
dataflow/pattern checks our Semgrep pattern rules can't fully cover. It is
**language-gated** via `applicable(config)` — it only runs when `python` is in
the config's detected languages, so mixed repos get Bandit only on their Python
part. Known ids map to teardowns (B608 → TD-033 SQLi, B60x shell → TD-042,
B105/B106 → TD-016) so they dedup + corroborate with semgrep/gitleaks by
`teardownId`+file:line; every other Bandit id is a hygiene advisory. Noisy ids
that carry no security signal (`B101` assert usage, `B110` try/except-pass) are
dropped entirely rather than cluttering the advisory section.

A **`gosec` provider** (optional, single binary) gives Go the same coverage via
its taint/pattern rules. Also language-gated (`go` in the detected languages),
and requires a `go.mod`/`go.sum` at the repo root (subdir Go modules are a
documented limitation). G201/G202/G701 → TD-033, G204/G702 → TD-042, G101 →
TD-016; everything else is advisory. Caveat (verified on gosec 2.30.0): its SQL
rules are **taint-driven** — they fire only when input traces to a real source
(`os.Args`/`http.Request`), so plain function parameters are not flagged; and
G101 hardcoded-credential detection is name-pattern based, so gitleaks/trivy
remain the reliable TD-016 net on Go.

A **`phpstan` provider** (optional, single pinned PHAR — needs PHP ≥ 8.1) gives
PHP the structural/type checks Semgrep can't: undefined classes, methods and
functions — the hallmark of AI hallucination. Gated: runs only when
`vendor/autoload.php` exists (a composer-installed app). Framework apps need the
matching extension (larastan, phpstan-symfony, phpstan-doctrine) — the app's own
`vendor/` copy is used when present, else the engine's vendored copy
(`rules/vendored/phpstan/`, pinned by `scripts/vendor-phpstan-extensions.mjs`) is
loaded via `--autoload-file` + neon `includes:`. Larastan is deliberately NOT
vendored (it needs the app's own Illuminate/container), so a Laravel app without
larastan is skipped with a note. A minimal level-5 neon is generated in the OS
temp dir (Pimcore's dynamic-constants stub included). Only the hallucination
class is reported (`*.notFound` / `*.undefined` identifiers); style (ergebnis/*)
and type-mismatch noise is dropped, so the QA advisory section stays a sharp
signal. All phpstan findings are **advisories** (unscored).

**Catalog enrichment (single source of truth for scoring):** every finding that
maps to a `teardownId` — from semgrep, bandit or gosec — is enriched from
`catalog/teardowns.json` (`src/catalog.mjs` → `enrichTeardowns`): its `severity`,
`pillar` and `fixSummary` come from the catalog, never from the tool's own
severity guess. This keeps scoring consistent — a command injection scores
`critical` whether semgrep, bandit or gosec flagged it — and fills the
`fixSummary` for bandit/gosec findings that previously shipped without one.

**Language-native SAST scope note:** Psalm is deliberately **not** wired — the
vendored Semgrep PHP packs + phpstan cover the same classes, and Psalm false
positives heavily on framework-heavy PHP (e.g. Pimcore). `p/phpcs-security-audit`
needs no separate vendoring: its nine rules are a curated subset of the
`php/lang` pack already committed. PHP variants now exist for every TD with a
PHP-expressible pattern (TD-002 LLM raw fetch and TD-050 payment webhook
included).

### 5.8 Setup & onboarding (the installer)

> **Terminology:** we call the setup experience **onboarding** — it is inviting,
> welcoming, and reads as "come on in", not "go configure your machine".

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
- Findings inside test/fixture files are **reported but not scored** — test code
  is not shipped, but a real key committed to a test file is still public in git
  and is flagged in its own report section.
- Criticals impose a **hard floor** (e.g. any critical → tier cannot be green), so "readiness" stays truthful.
- **Advisory findings are reported but not scored.** A finding carries an
  `advisory` flag when it is a heuristic or policy signal rather than a proven
  defect — a committed secret in a conventional config file, a dependency
  declared with a floating version, a deprecated DOM-write API. The rule of
  thumb: *deterministic defects score; heuristic/policy signals advise.*
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

> **Shipped beyond v1's 8:** TD-050 (unverified payment webhook, TS/Python),
> TD-051 (client-supplied entitlement, TS/PHP), and the 2026-11-17
> Reelvenue-derived rules — TD-052 (reactive read/write loop, TS/JS), TD-054
> (silent failure into a falsy default, TS/JS), TD-055 (webhook signature
> conflation, TS/JS) — plus the provider-driven TDs — TD-016 (Gitleaks),
> TD-019 (scc), TD-021 (Madge), TD-017 (tests heuristic). The "8 rules" table
> above is the original Semgrep matrix, not the current ceiling. TD-053
> (Firestore rule/query mismatch) ships as part of TD-008's provider
> cross-check, not as a standalone Semgrep rule. See
> `docs/reelvenue-derived-work.md` for the full derivation.

### 7.2 Detectability split (full catalog, 40 TDs)

- **~25 statically detectable** via Semgrep: TD-002, 004, 006, 007, 008, 009, 016, 018, 019, 020, 022, 026, 030, 031, 032, 033, 034, 035, 036, 037, 038, 039, 040, 041, 042, 043, 044, 045, 046…
- **~14 not statically detectable** (behavioral/architectural): TD-014 (prompt injection), 027 (runaway agent), 028 (contract regression), 047/048/049 (logic/race)… → reported as "see Environment guide rules 16–22", not scored.
- **Partially detectable** — TD-017 (hallucinated tests) has a heuristic: the `tests` provider flags test files with no assertion calls (§8.1). TD-021 (pattern fragmentation) is approximated by Madge's circular-dependency graph.
- **A third case — "detectable, but not in your language":** a TD may have a Semgrep variant for one language but not another (e.g. TD-046 only exists for Python). The report distinguishes "not detectable at all" from "not covered for your stack", so coverage gaps are honest, never silent zeros.

For the role-based view — what each of the three LastMile roles (Auditor /
Architect / Hardener) gets from the scanner, what's planned, and what is out of
static reach (runtime behavior, ops, compliance) — see
`docs/scanner-capabilities.md`.

### 7.3 Golden tests (the credibility gate)

Every rule must pass a **golden test harness**:

- `vulnerableCode` from the TD → rule **fires**.
- `hardenedCode` from the TD → rule **silent** (no false positive).

No rule ships until both assertions pass. This is what prevents the scanner from being dismissed as noisy.

### 7.4 Best tool per TD (which provider flags what)

| TD | Preferred provider (over Semgrep) |
|---|---|
| TD-016 (hardcoded secrets) | **Gitleaks** (adopted — entropy + allowlists; overlaps Semgrep's prefix regex, dedup collapses) |
| TD-037 / TD-038 / TD-039 (Python RCE/SSTI) | Bandit (adopted — `B307` eval / `B301`–`B303` pickle fire as advisory today; not yet mapped to TD-037/038/039) |
| TD-033 / TD-042 (SQLi / command injection) | taint — **Bandit** (adopted, Python) · **gosec** (adopted, Go) · CodeQL (later, needs build) |
| TD-041 (prototype pollution) | CodeQL (JS) |
| TD-014 (prompt injection) | Garak / Promptfoo (dynamic) |
| TD-019 (monolithic file) | **scc** (adopted — file-size threshold, `ruleParams.maxFileLines`) |
| TD-021 (pattern fragmentation) | **Madge** (adopted — circular deps) |
| TD-044 (floating promise / unhandled rejection) | **deferred to type-aware linter** — ESLint `no-floating-promises` |
| Language linter (QA hygiene) | **ESLint** (adopted — JS only, core rules; TypeScript + TD-044 pending typescript-eslint) |
| Runtime infra (Dockerfile, root user, healthcheck) | Trivy config / hadolint |
| Go reachable vulns | govulncheck |

> **TD-044 deferred to the linter (why):** a pattern-mode Semgrep rule can't
distinguish a call that returns a Promise (e.g. `db.insertEvent(...)`) from a
harmless fire-and-forget call, so it would be noisy — violating
precision-over-volume. The type-aware ESLint `no-floating-promises` rule sees
real types and flags only genuinely-unhandled promises.

> **TD-026 is NOT a Gitleaks target:** despite the old "secrets" grouping, TD-026
is env-inheritance — an agent dumping `process.env` (or a committed `.env`) to a
log. That's a Semgrep pattern (`console.log(process.env)`, committed `.env`), not
entropy-based secret scanning. Tracked as a separate rule backlog item.

### 7.5 Always-on hygiene rules (LastMile hardening)

Beyond the teardown matrix, the engine ships an **always-on** hygiene rulepack
(`rules/hygiene/*.yaml`) for the LastMile "Hardener" framework. These are
language-gated (JS/TS + Python today), carry `metadata.peek.hygiene = true`, and
map to `kind: 'hygiene'` findings with `teardownId: null`. The same golden-harness
gate (§7.3) applies.

| Rule | Sinks | Severity | Scored? |
|---|---|---|---|
| `xss-dangerously-set-html` | React `dangerouslySetInnerHTML` | high | scored |
| `eval` | `eval` / `new Function` (JS), `eval`/`exec` (Py) | high | scored |
| `open-redirect` | `res.redirect(req.*)` (Express), Flask/Django `redirect(request.*)` | high | scored |
| `xss-dom-write` | `document.write` / `insertAdjacentHTML` | medium | **advisory** |

`innerHTML = <variable>` is deliberately **not** a rule: it is idiomatic DOM code
and only taint mode can prove the value is attacker-controlled (it fired ~67
times on a real Pimcore app — the same precision-over-volume deferral as TD-044).

---

## 8. Report output

`AUDIT-REPORT.md` (human) + `peek-report.json` (machine / agent-consumable).

```markdown
# Local Deep Code Audit Report
**Date:** 2026-11-14
**Engine:** vibe-check 0.1.0 (public, commit <hash>)

## Verdict
Your code scores **142/350** — Needs Hardening; the top issue is **lookup by raw
id without tenant scope** (3 critical).
Your dependencies carry **12 known CVE(s)**; the worst is critical `proxy-addr`
— upgrade to fix.

## Overall Risk
- Your code: 142 / 350 — 🟡 Needs Hardening
- Dependencies: 12 known CVE(s) — 1 critical, 6 high, 5 medium (reported separately)

## App Stack
Detected: Firebase (Firestore database, Cloud Functions) · React frontend · Stripe payments.

## Agent Provenance
Official AI-coding tool markers detected:
- Claude Code (CLAUDE.md)
- Claude Code (Co-Authored-By commit trailer)
Agent-workflow log files you asked to watch:
- `docs/BUILD_RUN_2026-11-16.md`

## Findings Summary
| Check | Findings | What |
| --- | ---: | --- |
| semgrep | 4 | TD-008 ×3, TD-002 ×1 |
| ... | | |

## Pillar Breakdown
| Pillar | Risk Score | Max |
| ... |

## External Dependencies (CVEs)
| Severity | Package | Version | CVEs | Fix |
| ... |

## Findings (your code)
### security
- **TD-008** (`src/app/api/users/route.ts:41`): lookup by raw id without tenant scope
  - message: what's wrong, in one line
  - Fix: the one-line remediation
  → see https://peek.software/teardowns/TD-008

## Findings in test files (not scored)
_Test code is not shipped, so these do not affect the score — but a real secret
committed to a test file is still public in git._
### security
- **TD-016** (`src/keys.test.ts:3`): Hardcoded secret (aws-access-token)
  → see https://peek.software/teardowns/TD-016

## Advisories (not scored)
_Heuristic / policy signals — reported for awareness, never counted toward the score._
### security
- **xss-dom-write** (`public/js/app.js:2`): XSS — raw HTML injected into the DOM

## Not Statically Verifiable
- TD-014 (prompt injection) — see guide rule 16

## Next Steps
- Get It Fixed by Last Mile → ...
```

`peek-report.json` findings carry `{ id, file, line, severity, pillar, teardownId, message, fixSummary }` so an agent can be instructed: *"Read `peek-report.json` and fix every flagged teardown without breaking tests."*

### 8.1 Test signal (QA pillar)

A pure-Node `tests` provider adds two deterministic, offline facts about tests —
it **never executes them** (running tests would break the offline principle):

- **Presence** — no test files under the scanned targets → a `medium` QA hygiene
  finding ("No unit tests detected"). The QA pillar otherwise has no signal.
- **Assertions** — a test file with no recognizable assertion call
  (`expect(`, `assert…`, `.should`, `fail(`…) → a `low` TD-017 finding
  ("Test file with no assertions"). Heuristic: path conventions + an
  assertion-call whitelist, so it is scored low and worded as a signal, not a
  proof.
- **Scoring boundary** — other providers' findings that land *inside* test files
  (e.g. a hard-coded key gitleaks finds in `keys.test.ts`) are reported in their
  own "not scored" section, never counted toward the risk score. The two signals
  above are the only test-file findings that score.

---

## 9. Implementation plan (draft)

- ✅ **Phase 0 — contract.** `peek-report.json` + config schemas + the facts snapshot format; scoring constants frozen (imported from the quiz).
- ✅ **Phase 1 — engine skeleton.** CLI, config loader, provider registry (Semgrep + OSV-Scanner + Madge + scc + Gitleaks + ESLint + tests), finding dedup, pillar mapping, Markdown renderer, offline/deterministic guarantees.
- ✅ **Phase 2 — golden rulepack.** TD-002/008/016/032/033/042/045/046/050/051 across JS/TS/Python/PHP + the golden harness; `catalog/teardowns.json` vendored.
- 🚧 **Phase 3 — config generator (peek.software).** Backend `deriveTargets` + `targets` param landed (uncommitted); the full quiz→config→scan flow still needs end-to-end testing and likely extension.
- ✅ **Phase 4 — calibration overlay.** Engine-side `computeCalibration` + the report overlay render end-to-end (config `quiz` block → self-report vs. scan table + per-hotspot ⚠️/✅ moments). The peek.software backend passes the quiz block through verbatim (`generateScanConfig`), and its `totalScore`/`pillarBreakdown`/`hotspots` shape matches the engine's expectation — verified against the sample config.
- ✅ **Tenant discovery (data-layer parsers, 2026-11-17).** Prisma relation-graph + SQL-migrations parsers (`src/tenant/`) produce a tenant descriptor (aggregate root + scope columns + scoped/global entities); TD-008 materializes a precise rule for Prisma and reports "not statically verifiable" (naming the tenant) for raw SQL. `ruleParams.tenantColumn` is the manual override.
- ✅ **Firestore rule/query cross-check.** `firestore.rules` parsing (`src/firestore/scope.mjs`) + Firestore query cross-check → `rule-query-mismatch` finding (TD-008).
- ✅ **PostgreSQL/Supabase RLS check (2026-11-22).** `src/providers/rls.mjs` parses SQL migrations and flags tables whose row-level security is never enabled (including the inert-policies case: `CREATE POLICY` without `ENABLE ROW LEVEL SECURITY`). Gated on `supabase`/`postgres` stack markers or Postgres-only DDL — MySQL repos can't trip it. Golden-style unit tests cover ENABLE/DISABLE/FORCE ordering, quoted policy names, and comment stripping.
- ✅ **Reelvenue-derived rule batch.** TD-052/054/055 shipped (golden-tested) + peek-software teardowns TD-052..TD-056; TD-053 folded into TD-008. See `docs/reelvenue-derived-work.md`.
- ✅ **Agent-provenance detection (2026-11-17).** `src/agent-provenance.mjs` reports OFFICIAL AI-tool markers only — instruction/config files (`CLAUDE.md`, `.cursorrules`, `.cursor/rules`, `.github/copilot-instructions.md`, `.aider.conf.yml`, `AGENTS.md`) and Claude Code git commit trailers (`Co-Authored-By: Claude <noreply@anthropic.com>`, `Claude-Session:`). Project-specific workflow logs are NOT hard-coded — the user names them via `ruleParams.agentLogPatterns` (glob-like) and they are reported verbatim under "Agent Provenance".
- ✅ **Live deployment probe (2026-11-22).** Opt-in `vibe-check probe <url>` (`src/probe.mjs`) — read-only GET/HEAD with redirect cap + per-request timeout, loopback/private targets rejected. Checks final-HTTPS transport, deployed security headers, wildcard CORS, cookie flags, server disclosure (`X-Powered-By`), exposed `/.env`/`/.git/HEAD`, public source maps (SPA-fallback guard), and debug/docs endpoints. Reported separately from the offline code audit, never scored. Own implementation — ideas from competitor READMEs, see `docs/comparison.md`.
- ⬜ **Structured cross-checking (idea — pick up with the multi-agent-loop work).** Today the agent-workflow log files are provenance only. If a harness later emits its findings in a machine-readable shape (e.g. a checklist line `- [x] TD-052 — fixed in <file>`), the scanner could post-check each claim against the code — a self-report-vs-code calibration (the same overlay as §3 level 2, but fed by the agent's own structured notes instead of the quiz). Requires the harness to emit structured output; never inferred from free-form prose.
- ⬜ **Phase 5 — parameterized rules + full detectable catalog.**

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
