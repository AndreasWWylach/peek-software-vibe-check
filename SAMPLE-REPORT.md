# Example scan report

This is a real, lightly redacted report produced by `vibe-check run` against a marketplace app under development — the app of the [marketplace-rebuild case study](https://peek.software/case-study/marketplace-rebuild). It shows what a scanned repo receives: verdict, risk score, agent provenance, findings with fix summaries, advisories, CVEs, and the AI-remediation FIX-PROMPTS companion ([SAMPLE-FIX-PROMPTS.md](SAMPLE-FIX-PROMPTS.md)).
**Date:** 2026-11-23
**Engine:** peek.software vibe-check 0.1.0 (public, commit a306f62)

## Verdict
Your code scores **133/350** — Needs Hardening; the top issue is **Firestore has no security rules** (2 critical).
Your dependencies carry **18 known CVE(s)**; the worst is critical `proxy-addr` — upgrade to fix.

## Go-Live Readiness
**🔴 Please review before going live**
- 2 critical dependency CVE(s) — patch before launch.
- 9 high dependency CVE(s) — upgrade before launch.
- CI runs tests without a coverage gate.
- App Check enforcement is off — callables do not verify the client.
- 1 check(s) disabled — re-run with them enabled to complete the score.

## Overall Risk
- **Your code:** 133 / 350 — 🟡 Needs Hardening
- **Dependencies:** 18 known CVE(s) — 2 critical, 9 high, 7 medium (reported separately below)

## App Stack
Detected: Firebase (Firestore database, Cloud Functions, Storage) · React + Vite frontend · Stripe payments.

## Agent Provenance
Official AI-coding tool markers detected:
- Claude Code (Claude-Session commit trailer)
- Claude Code (Co-Authored-By commit trailer)
Agent-workflow log files you asked to watch:
- `docs/BUILD_RUN_2026-11-01.md`
- `docs/UI_REVIEW_2026-11-02.md`

## Findings Summary
| Check | Findings | What |
| --- | ---: | --- |
| semgrep | 22 · 1 advisory · 1 in tests | TD-054 ×22 · advisory: xss-dom-write ×1 · test files: TD-016 ×1 |
| gitleaks | 0 | — |
| trivy | 0 · 3 advisory | advisory: stripe-secret-token ×1, twilio-api-key ×1, sendgrid-api-token ×1 |
| firebase | 6 | TD-008 ×2, TD-032 ×4 |
| madge | 1 | TD-021 ×1 |
| deps | 0 | — |
| headers | 0 | — |
| ci | 0 · 1 advisory | advisory: no-coverage ×1 |
| checkov | 0 · 2 advisory | advisory: CKV_DOCKER_3 ×1, CKV_DOCKER_2 ×1 |
| hadolint | 0 · 1 advisory | advisory: DL3008 ×1 |
| bandit | 0 | — |
| gosec | 0 | — |
| phpstan | 0 | — |
| scc | 0 | — |
| eslint | 0 | — |
| tests | 0 | — |
| OSV-Scanner | 18 CVE(s) | 2 critical, 9 high, 7 medium — see External Dependencies |
_8 advisory finding(s) are reported below and are not scored._

## Pillar Breakdown
| Pillar | Risk Score | Max |
| --- | ---: | ---: |
| Security & Secret Hygiene | 33 | 90 |
| Runtime Behavior & Infrastructure | 90 | 90 |
| Software Design & Architecture | 10 | 90 |
| Testing & Quality Assurance | 0 | 80 |

_How this is scored: each finding adds points by severity — critical 20, high 10, medium 5, low 2 — to its pillar (capped at the pillar max). Dependency CVEs are not part of this score; they are reported separately below._

## Self-Report vs. Scan
- Self-reported: 0 / 350 — 🟢 Looks Solid
- Scan: 133 / 350 — 🟡 Needs Hardening

| Pillar | Self-report | Scan |
| --- | ---: | ---: |
| Security & Secret Hygiene | 0 | 33 |
| Runtime Behavior & Infrastructure | 0 | 90 |
| Software Design & Architecture | 0 | 10 |
| Testing & Quality Assurance | 0 | 0 |

## External Dependencies (CVEs)
| Severity | Package | Version | CVEs | Fix |
| --- | --- | --- | --- | --- |
| critical | `proxy-addr` *(confirmed by trivy)* | 2.0.7 | CVE-2026-90711, GHSA-jqcg-44mw-7w3h | Upgrade proxy-addr beyond 2.0.7 |
| critical | `shell-quote` | 1.10.0 | CVE-2026-102422, GHSA-pqg4-j6r4-53mv | Upgrade shell-quote beyond 1.10.0 |
| high | `@fastify/busboy` *(confirmed by trivy)* | 3.2.0 | CVE-2026-19481, CVE-2026-19484, CVE-2026-74866 … +3 more | Upgrade @fastify/busboy beyond 3.2.0 |
| high | `@grpc/grpc-js` *(confirmed by trivy)* | 1.14.4 | CVE-2026-101915, CVE-2026-101916, GHSA-f596-whhp-79r4 … +1 more | Upgrade @grpc/grpc-js beyond 1.14.4 |
| high | `body-parser` *(confirmed by trivy)* | 2.3.0 | CVE-2026-111181, GHSA-27r3-jxmh-p828 | Upgrade body-parser beyond 2.3.0 |
| high | `brace-expansion` *(confirmed by trivy)* | 1.1.18 | CVE-2026-102276, CVE-2026-102277, CVE-2026-102278 … +3 more | Upgrade brace-expansion beyond 1.1.18 |
| high | `re2js` *(confirmed by trivy)* | 2.8.6 | CVE-2026-116795, GHSA-gg6h-894w-4m9c | Upgrade re2js beyond 2.8.6 |
| high | `source-map-js` *(confirmed by trivy)* | 1.2.1 | CVE-2026-93749, GHSA-68fv-2mgg-jv7q | Upgrade source-map-js beyond 1.2.1 |
| high | `uuid` *(confirmed by trivy)* | 9.0.1 | CVE-2026-41907, CVE-2026-41988, GHSA-w5hq-g745-h8pq | Upgrade uuid beyond 9.0.1 |
| high | `vite` | 7.3.6 | CVE-2026-112942, CVE-2026-112943, CVE-2026-112944 … +7 more | Upgrade vite beyond 7.3.6 |
| high | `zod` | 4.4.1 | CVE-2023-54404, GHSA-mrhx-c7xc-m3w5 | Upgrade zod beyond 4.4.1 |
| medium | `fast-xml-parser` *(confirmed by trivy)* | 5.11.2 | CVE-2026-126066, GHSA-474x-hrwr-fgx4 | Upgrade fast-xml-parser beyond 5.11.2 |
| medium | `glob` *(confirmed by trivy)* | 10.5.0 | CVE-2026-118773, GHSA-3g3m-2fjr-6pw4 | Upgrade glob beyond 10.5.0 |
| medium | `minimatch` *(confirmed by trivy)* | 9.0.9 | CVE-2026-118764, GHSA-g3hv-75wg-m249 | Upgrade minimatch beyond 9.0.9 |
| medium | `@vitest/mocker` | 5.0.0 | CVE-2026-112949, CVE-2026-112950, GHSA-qxg6-89mg-rqv8 … +1 more | Upgrade @vitest/mocker beyond 5.0.0 |
| medium | `fast-uri` | 3.1.7 | CVE-2026-110095, CVE-2026-110180, CVE-2026-110306 … +7 more | Upgrade fast-uri beyond 3.1.7 |
| medium | `postcss-selector-parser` *(confirmed by trivy)* | 6.1.4 | CVE-2026-104844, GHSA-rj75-hqrm-r3gf | Upgrade postcss-selector-parser beyond 6.1.4 |
| medium | `qs` *(confirmed by trivy)* | 6.16.0 | CVE-2026-110816, GHSA-6pq8-jhm2-2vcw | Upgrade qs beyond 6.16.0 |

## Findings (your code)

### 🔒 Security & Secret Hygiene
- 🔴 **TD-008** · `firestore.rules` — Firestore has no security rules
  - The frontend reads/writes Firestore directly via the client SDK, but no `firestore.rules` is checked in — the access-control boundary is unverifiable (test-mode rules, console-managed rules, or rules maintained in a sibling repo of a shared Firebase project).
  - 🔧 Fix: Add `firestore.rules` requiring `request.auth` and tenant-scoped paths, then deploy it via firebase.json — or route all data access through authenticated Cloud Functions. For a shared project, keep the fenced per-product rules section in the sibling repo that deploys them, and verify it covers this app's collections.
  → https://peek.software/teardowns/TD-008

- 🟡 **TD-008** · `storage.rules` — Storage has no security rules
  - No `storage.rules` file is checked in. If all Storage access is server-side (Admin SDK), the boundary lives in the function code — verify every function authenticates its caller. For a shared Firebase project, the rules may live in a sibling repo.
  - 🔧 Fix: Add `storage.rules` requiring `request.auth` and tenant-scoped paths, then deploy it via firebase.json — or route all data access through authenticated Cloud Functions. For a shared project, keep the fenced per-product rules section in the sibling repo that deploys them, and verify it covers this app's collections.
  → https://peek.software/teardowns/TD-008

- 🔵 **TD-032** — Cloud Function handler with no visible auth check (4)
  - This file defines `onCall`/`onRequest` handlers but references no auth verification (`request.auth`, `verifyIdToken`, …) — verify it is intentionally public or gated another way (signed URLs, allowlists).
  - 🔧 Fix: Verify the caller with `context.auth` / `request.auth` or an explicit token check before touching data.
  → https://peek.software/teardowns/TD-032
  - `functions/src/authEmailFns.ts`
  - `functions/src/emailFns.ts`
  - `functions/src/sitemapFn.ts`
  - `functions/src/streamServe.ts`


### ⚙️ Runtime Behavior & Infrastructure
- 🟡 **TD-054** — Silent failure into a falsy default (22)
  - An async failure is swallowed into a falsy default — the error never surfaces.
  - 🔧 Fix: Surface the error, or return a discriminated result (ok plus message) so a failure is never read as a successful zero/empty state.
  → https://peek.software/teardowns/TD-054
  - `frontend/src/routes/admin/firebaseConsole.ts:228`
  - `frontend/src/routes/fan/firebaseDiscover.ts:373`
  - `frontend/src/routes/fan/firebaseScreeningDetail.ts:93`
  - `frontend/src/routes/fan/firebaseScreeningDetail.ts:114`
  - `frontend/src/routes/fan/firebaseScreeningDetail.ts:115`
  - `frontend/src/routes/fan/firebaseTickets.ts:182`
  - `frontend/src/routes/fan/firebaseTickets.ts:217`
  - `frontend/src/routes/fan/firebaseWatch.ts:134`
  - `frontend/src/routes/filmmaker/firebaseCreatorDashboard.ts:409`
  - `frontend/src/routes/filmmaker/firebaseFilmEdit.ts:579`
  - `frontend/src/routes/filmmaker/firebasePayments.ts:141`
  - `frontend/src/routes/filmmaker/firebasePayments.ts:166`
  - `frontend/src/routes/public/film.ts:59`
  - `frontend/src/routes/public/venue.ts:45`
  - `frontend/src/routes/shared/firebaseSettings.ts:219`
  - `frontend/src/routes/venue/firebaseVenueDashboard.ts:410`
  - `frontend/src/routes/venue/firebaseVenueRequests.ts:76`
  - `frontend/src/routes/venue/firebaseVenueSettlements.ts:88`
  - `frontend/src/shared/firebase/filmsApi.ts:193`
  - `frontend/src/shared/firebase/filmsApi.ts:197`
  - `functions/src/payments.ts:922`
  - `jobs/transcode/src/index.ts:234`


### 🏗️ Software Design & Architecture
- 🟠 **TD-021** · `frontend/src/shared/state/mfa.ts` — Circular dependency: frontend/src/shared/state/mfa.ts → frontend/src/shared/state/session.ts
  - Modules import each other in a cycle: frontend/src/shared/state/mfa.ts → frontend/src/shared/state/session.ts.
  - 🔧 Fix: Establish one core API client with runtime schema validation, and make every feature reuse it — one pattern, one source of truth, one place to add auth, retries, and logging.
  → https://peek.software/teardowns/TD-021


## Findings in test files (not scored)
_Test code is not shipped to production, so these do not affect the risk score — but a real secret committed to a test file is still public in git and worth fixing._

### 🔒 Security & Secret Hygiene
- 🔴 **TD-016** · `frontend/src/shared/components/asyncState.test.ts:46` — Hardcoded API key / secret
  - Hardcoded API key / secret literal — ship it to the browser and anyone can read it.
  - 🔧 Fix: Move the secret to the server; never ship the key to the browser.
  - 🤝 Confirmed by gitleaks (cross-tool agreement).
  → https://peek.software/teardowns/TD-016


## Advisories (not scored)
_Informational — these do not affect the risk score. They are noted for awareness, not as defects._

### 🔒 Security & Secret Hygiene
- 💡 **stripe-secret-token** · `.env:34` — Committed secret in config
  - Trivy detected a Stripe secret (rule: stripe-secret-token).
  - 🔧 Fix: Conventional secret placement — ensure the repo stays private (or gitignore this file) and rotate the value if the repo was ever public.

- 💡 **twilio-api-key** · `.env:43` — Committed secret in config
  - Trivy detected a Twilio secret (rule: twilio-api-key).
  - 🔧 Fix: Conventional secret placement — ensure the repo stays private (or gitignore this file) and rotate the value if the repo was ever public.

- 💡 **sendgrid-api-token** · `.env:49` — Committed secret in config
  - Trivy detected a SendGrid secret (rule: sendgrid-api-token).
  - 🔧 Fix: Conventional secret placement — ensure the repo stays private (or gitignore this file) and rotate the value if the repo was ever public.

- 💡 **xss-dom-write** · `frontend/src/routes/auth/requestAccess.ts:52` — XSS — raw HTML injected into the DOM
  - document.write / insertAdjacentHTML inject raw HTML — avoid with untrusted data.
  - 🔧 Fix: Avoid document.write() and insertAdjacentHTML(); build the DOM with textContent or a sanitizing renderer.


### ⚙️ Runtime Behavior & Infrastructure
- 💡 **CKV_DOCKER_3** · `jobs/transcode/Dockerfile:1` — Ensure that a user for the container has been created
  - 🔧 Fix: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/docker-policies/docker-policy-index/ensure-that-a-user-for-the-container-has-been-created

- 💡 **CKV_DOCKER_2** · `jobs/transcode/Dockerfile:1` — Ensure that HEALTHCHECK instructions have been added to container images
  - 🔧 Fix: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/docker-policies/docker-policy-index/ensure-that-healthcheck-instructions-have-been-added-to-container-images

- 💡 **DL3008** · `jobs/transcode/Dockerfile:13` — Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`


### 🧪 Testing & Quality Assurance
- 💡 **no-coverage** · `.github/workflows/ci.yml` — CI runs tests without a coverage gate
  - Tests run in CI, but no coverage tool (jest --coverage, pytest-cov, codecov, …) is referenced — coverage is not tracked or enforced.
  - 🔧 Fix: Add coverage instrumentation and fail the pipeline when coverage drops below a threshold.


## Fix Prompts
`FIX-PROMPTS.md` was written next to this report — 15 copy-paste remediation prompt(s), one per finding group.
Paste each section into any AI coding agent that can edit files — Claude Code, Cursor, Codex, aider, OpenCode with DeepSeek — or use the bundled `skills/vibe-check` Claude Code skill.
Every prompt ends with verification: re-run the scan and confirm the finding is gone — the fix is proven by the scanner, not claimed by the model.

## Skipped Checks
- **bandit** (not-applicable): Bandit (Python) does not apply to this app.
- **gosec** (not-applicable): gosec (Go) does not apply to this app.
- **phpstan** (not-applicable): PHPStan (PHP) does not apply to this app.

## Disabled Checks
_These checks were not scored — the risk score above does not cover them._
- **scc:TD-019** — monolithic-file detection (TD-019) is opt-in — set `ruleParams.maxFileLines` in the config to enable it.

## Not Statically Verifiable
- TD-008 — Query without tenant scope — Firestore access control is checked by the Firebase rules provider: open rules, missing auth, and a rule/query scope cross-check when `firestore.rules` and the client SDK live in the same repo. Tenant isolation across a shared Firebase project (rules maintained in a sibling repo) is not statically verifiable - review the fenced per-product rules sections manually.
