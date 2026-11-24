# Example fix prompts

This is the `FIX-PROMPTS.md` produced by the same scan as
[SAMPLE-REPORT.md](SAMPLE-REPORT.md) — a real, lightly redacted run against a
marketplace app under development — the app of the [marketplace-rebuild case study](https://peek.software/case-study/marketplace-rebuild). It shows the AI-remediation companion every
scan writes next to the report: one copy-paste prompt per finding group
(locations → what's wrong → fix → deep-dive link), each ending with
verification against the re-run scan. Each `## Fix N` section below is
standalone — copy it into the AI coding agent one section at a time.
**Date:** 2026-11-23
**Engine:** peek.software vibe-check 0.1.0 (public, commit a306f62)

---

# Fix Prompts — peek.software vibe-check remediation guide

Generated from `peek-report.json` (2026-11-23).
Copy ONE section at a time into any AI coding agent that can edit files —
Claude Code, Cursor, Codex, aider, OpenCode (incl. DeepSeek) — or use the
bundled Claude Code skill (`skills/vibe-check/`). Fix, verify, move on.

## Checklist (15 fixes)

- [ ] 1. TD-008: Firestore has no security rules — CRITICAL
- [ ] 2. TD-016: Hardcoded API key / secret — CRITICAL (test file, not scored)
- [ ] 3. stripe-secret-token: Committed secret in config — CRITICAL
- [ ] 4. Upgrade dependencies with known CVEs — CRITICAL
- [ ] 5. TD-021: Circular dependency: frontend/src/shared/state/mfa.ts → frontend/src/shared/state/session.ts — HIGH
- [ ] 6. TD-008: Storage has no security rules — MEDIUM
- [ ] 7. TD-054: Silent failure into a falsy default — MEDIUM
- [ ] 8. twilio-api-key: Committed secret in config — MEDIUM
- [ ] 9. sendgrid-api-token: Committed secret in config — MEDIUM
- [ ] 10. xss-dom-write: XSS — raw HTML injected into the DOM — MEDIUM
- [ ] 11. CKV_DOCKER_3: Ensure that a user for the container has been created — MEDIUM
- [ ] 12. CKV_DOCKER_2: Ensure that HEALTHCHECK instructions have been added to container images — MEDIUM
- [ ] 13. DL3008: Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>` — MEDIUM
- [ ] 14. TD-032: Cloud Function handler with no visible auth check — LOW
- [ ] 15. no-coverage: CI runs tests without a coverage gate — LOW

---

## Fix 1 — TD-008: Firestore has no security rules

**Locations:**
- `firestore.rules`

**What's wrong:**
The frontend reads/writes Firestore directly via the client SDK, but no `firestore.rules` is checked in — the access-control boundary is unverifiable (test-mode rules, console-managed rules, or rules maintained in a sibling repo of a shared Firebase project).

**Fix:**
Add `firestore.rules` requiring `request.auth` and tenant-scoped paths, then deploy it via firebase.json — or route all data access through authenticated Cloud Functions. For a shared project, keep the fenced per-product rules section in the sibling repo that deploys them, and verify it covers this app's collections.

**Deep dive:** https://peek.software/teardowns/TD-008

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 2 — TD-016: Hardcoded API key / secret

**Locations:**
- `frontend/src/shared/components/asyncState.test.ts:46` — in a test/fixture file — reported, not scored

**What's wrong:**
Hardcoded API key / secret literal — ship it to the browser and anyone can read it.

**Fix:**
Move the secret to the server; never ship the key to the browser.

**Deep dive:** https://peek.software/teardowns/TD-016

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 3 — stripe-secret-token: Committed secret in config

**Locations:**
- `.env:34` — advisory — reported, not scored

**What's wrong:**
Trivy detected a Stripe secret (rule: stripe-secret-token).

**Fix:**
Conventional secret placement — ensure the repo stays private (or gitignore this file) and rotate the value if the repo was ever public.

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 4 — Upgrade dependencies with known CVEs

**Affected packages:**
- `proxy-addr` [npm] (CVE-2026-90711, GHSA-jqcg-44mw-7w3h)
- `shell-quote` [npm] (CVE-2026-102422, GHSA-pqg4-j6r4-53mv)
- `@fastify/busboy` [npm] (CVE-2026-19481, CVE-2026-19484, CVE-2026-74866, GHSA-gxm5-99cw-xjw9, GHSA-x8mw-p69m-v3mx, GHSA-xjh9-v7x6-24jw)
- `@grpc/grpc-js` [npm] (CVE-2026-101915, CVE-2026-101916, GHSA-f596-whhp-79r4, GHSA-m9gg-hp2v-232j)
- `body-parser` [npm] (CVE-2026-111181, GHSA-27r3-jxmh-p828)
- `brace-expansion` [npm] (CVE-2026-102276, CVE-2026-102277, CVE-2026-102278, GHSA-6j4f-fj2g-mc7p, GHSA-q2hr-2g5m-vwhr, GHSA-qhr7-859c-m2p7)
- `re2js` [npm] (CVE-2026-116795, GHSA-gg6h-894w-4m9c)
- `source-map-js` [npm] (CVE-2026-93749, GHSA-68fv-2mgg-jv7q)
- `uuid` [npm] (CVE-2026-41907, CVE-2026-41988, GHSA-w5hq-g745-h8pq)
- `vite` [npm] (CVE-2026-112942, CVE-2026-112943, CVE-2026-112944, CVE-2026-112945, CVE-2026-112946, GHSA-587h-7wmj-h5pm, GHSA-698v-4r3x-3vcv, GHSA-9jrq-w75r-8gcw, GHSA-r825-w8mm-5pxw, GHSA-rq7h-c2jc-7f22)
- `zod` [npm] (CVE-2023-54404, GHSA-mrhx-c7xc-m3w5)
- `fast-xml-parser` [npm] (CVE-2026-126066, GHSA-474x-hrwr-fgx4)
- `glob` [npm] (CVE-2026-118773, GHSA-3g3m-2fjr-6pw4)
- `minimatch` [npm] (CVE-2026-118764, GHSA-g3hv-75wg-m249)
- `@vitest/mocker` [npm] (CVE-2026-112949, CVE-2026-112950, GHSA-qxg6-89mg-rqv8, GHSA-xp26-3454-mjgp)
- `fast-uri` [npm] (CVE-2026-110095, CVE-2026-110180, CVE-2026-110306, CVE-2026-110725, CVE-2026-86472, GHSA-333x-w4r6-6crp, GHSA-hrr3-gc8f-f4qj, GHSA-w74x-v6f9-j3xg, GHSA-wjr9-j795-jxcr, GHSA-xhq7-xmqj-769h)
- `postcss-selector-parser` [npm] (CVE-2026-104844, GHSA-rj75-hqrm-r3gf)
- `qs` [npm] (CVE-2026-110816, GHSA-6pq8-jhm2-2vcw)

**Fix:** Upgrade every package above to a version that resolves the listed
CVEs — prefer the latest patched release in the same major range, then
re-run the dependency lockfile install. Never pin to a version the
advisory says is still affected.
**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 5 — TD-021: Circular dependency: frontend/src/shared/state/mfa.ts → frontend/src/shared/state/session.ts

**Locations:**
- `frontend/src/shared/state/mfa.ts`

**What's wrong:**
Modules import each other in a cycle: frontend/src/shared/state/mfa.ts → frontend/src/shared/state/session.ts.

**Fix:**
Establish one core API client with runtime schema validation, and make every feature reuse it — one pattern, one source of truth, one place to add auth, retries, and logging.

**Deep dive:** https://peek.software/teardowns/TD-021

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 6 — TD-008: Storage has no security rules

**Locations:**
- `storage.rules`

**What's wrong:**
No `storage.rules` file is checked in. If all Storage access is server-side (Admin SDK), the boundary lives in the function code — verify every function authenticates its caller. For a shared Firebase project, the rules may live in a sibling repo.

**Fix:**
Add `storage.rules` requiring `request.auth` and tenant-scoped paths, then deploy it via firebase.json — or route all data access through authenticated Cloud Functions. For a shared project, keep the fenced per-product rules section in the sibling repo that deploys them, and verify it covers this app's collections.

**Deep dive:** https://peek.software/teardowns/TD-008

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 7 — TD-054: Silent failure into a falsy default

**Locations:**
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

**What's wrong:**
An async failure is swallowed into a falsy default — the error never surfaces.

**Fix:**
Surface the error, or return a discriminated result (ok plus message) so a failure is never read as a successful zero/empty state.

**Deep dive:** https://peek.software/teardowns/TD-054

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 8 — twilio-api-key: Committed secret in config

**Locations:**
- `.env:43` — advisory — reported, not scored

**What's wrong:**
Trivy detected a Twilio secret (rule: twilio-api-key).

**Fix:**
Conventional secret placement — ensure the repo stays private (or gitignore this file) and rotate the value if the repo was ever public.

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 9 — sendgrid-api-token: Committed secret in config

**Locations:**
- `.env:49` — advisory — reported, not scored

**What's wrong:**
Trivy detected a SendGrid secret (rule: sendgrid-api-token).

**Fix:**
Conventional secret placement — ensure the repo stays private (or gitignore this file) and rotate the value if the repo was ever public.

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 10 — xss-dom-write: XSS — raw HTML injected into the DOM

**Locations:**
- `frontend/src/routes/auth/requestAccess.ts:52` — advisory — reported, not scored

**What's wrong:**
document.write / insertAdjacentHTML inject raw HTML — avoid with untrusted data.

**Fix:**
Avoid document.write() and insertAdjacentHTML(); build the DOM with textContent or a sanitizing renderer.

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 11 — CKV_DOCKER_3: Ensure that a user for the container has been created

**Locations:**
- `jobs/transcode/Dockerfile:1` — advisory — reported, not scored

**What's wrong:**
Ensure that a user for the container has been created

**Fix:**
https://docs.prismacloud.io/en/enterprise-edition/policy-reference/docker-policies/docker-policy-index/ensure-that-a-user-for-the-container-has-been-created

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 12 — CKV_DOCKER_2: Ensure that HEALTHCHECK instructions have been added to container images

**Locations:**
- `jobs/transcode/Dockerfile:1` — advisory — reported, not scored

**What's wrong:**
Ensure that HEALTHCHECK instructions have been added to container images

**Fix:**
https://docs.prismacloud.io/en/enterprise-edition/policy-reference/docker-policies/docker-policy-index/ensure-that-healthcheck-instructions-have-been-added-to-container-images

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 13 — DL3008: Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`

**Locations:**
- `jobs/transcode/Dockerfile:13` — advisory — reported, not scored

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 14 — TD-032: Cloud Function handler with no visible auth check

**Locations:**
- `functions/src/authEmailFns.ts`
- `functions/src/emailFns.ts`
- `functions/src/sitemapFn.ts`
- `functions/src/streamServe.ts`

**What's wrong:**
This file defines `onCall`/`onRequest` handlers but references no auth verification (`request.auth`, `verifyIdToken`, …) — verify it is intentionally public or gated another way (signed URLs, allowlists).

**Fix:**
Verify the caller with `context.auth` / `request.auth` or an explicit token check before touching data.

**Deep dive:** https://peek.software/teardowns/TD-032

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---

## Fix 15 — no-coverage: CI runs tests without a coverage gate

**Locations:**
- `.github/workflows/ci.yml` — advisory — reported, not scored

**What's wrong:**
Tests run in CI, but no coverage tool (jest --coverage, pytest-cov, codecov, …) is referenced — coverage is not tracked or enforced.

**Fix:**
Add coverage instrumentation and fail the pipeline when coverage drops below a threshold.

**Scope:**
- Fix every location listed above.
- Then search this codebase for the same pattern and fix those occurrences too.
- Do not change unrelated behavior, and keep the public API/UX identical.

**Verify:**
- Re-run the same `vibe-check run --config <your-config>` that produced this report.
- Confirm none of the locations above is reported again.
- Run the project's own test suite.

---


When every box above is ticked, record the result in the team's run log
(e.g. `docs/BUILD_RUN_<date>.md`) as `- [x] <finding id> — fixed in <file>`,
or `- [ ] <finding id> — false positive, <why>` when you intentionally left it.
A later scan can then cross-check each claim against the code.
