# Reelvenue-derived work — 2026-11-17

Source: Jaice's update `53da38d..372413a` (north-star build run + follow-ups +
a 16-finding UI-review pass + a login fix). Jaice runs a **multi-agent loop**:
build agent(s) ship per phase, then an independent UI-review pass walks every
page and catches what the build + 395 functions tests + 295 frontend tests
missed. Detailed notes: `/memories/repo/reelvenue-scan-insights.md`.

This page channels the findings into three workstreams. One finding may feed
all three.

---

## A. Scanner improvements (this repo)

### A1 — New teardown rules (Semgrep, `rules/peek/<TD>/`)

| TD | Defect | Scanable signal | Source (vulnerable → hardened) |
|---|---|---|---|
| **TD-052** | Reactive read/write loop | `onSnapshot`/`watch` callback that writes to Firestore (or triggers a re-render) | `frontend/src/main.app.ts` (unread badge → route re-render; 44 renders/46 writes in 5 s → `paintThreadBadges` in place) |
| **TD-053** | Security-rule / query mismatch | Firestore query missing the field `firestore.rules` requires (`permission-denied`) | `frontend/src/shared/firebase/mediaApi.ts` (`watchFilmAssets` query without `ownerUid` → constrained) |
| **TD-054** | Silent error → falsy default | `catch {}` / `.catch(() => 0)` returning a default where an error must surface | staff console route (callable refused with 2FA, console showed "0 pending") |
| **TD-055** | Webhook signature conflation | a request with **no** signature header treated as a **failed** signature | `functions/src/stripeWebhookEndpoints.ts` (+ `stripeWebhookEndpoints.test.ts`) |

- TD-052/054/055 are pure Semgrep rules (`typescript.yaml`) + golden fixtures.
- **TD-053 is provider work**, not a single rule: it needs the Firestore rules
  as context. Extend `src/providers/firebase.mjs` to parse `firestore.rules`
  and flag queries that don't constrain by the rule-required fields.

### A2 — Enrich existing rules

- **TD-048 (invite-gate race)** already exists — add the new instance: sign-in
  resolves before the session sync hydrates → bounce → second attempt signs in
  a *different* account. Source: `frontend/src/routes/auth/firebaseLogin.ts` +
  the new `frontend/src/shared/state/sessionWait.ts` (the hardened pattern).

### A3 — Hygiene (no teardown fact)

- Missing-vs-invalid signature could also ship as a **hygiene rule** first, and
  graduate to TD-055 once the catalog carries the fact.

---

## B. New teardowns (peek.software — EDIT ONLY, never commit)

Create catalog entries in `frontend/src/data/teardowns/catalogs/v1/en/`:

- `td-052-reactive-loop.json` — from `main.app.ts` (badge listener loop).
- `td-053-rule-query-mismatch.json` — from `mediaApi.ts`.
- `td-054-silent-falsy-default.json` — from the staff console.
- `td-055-webhook-signature-conflation.json` — from `stripeWebhookEndpoints.ts`.
- `td-056-state-copy-mismatch.json` — "Tickets on sale" while a campaign was
  still collecting pledges (educational only; no static rule).

Each teardown needs the standard shape: prompt, `vulnerableCode` (the pre-fix
Reelvenue code), `hardenedCode` (the post-fix code), `flaw`, `impact`, `lesson`.

Enrich existing: **td-048** (new login-bounce instance), **td-050** (the
signature nuance lives beside unverified-payment-webhook).

---

## C. Case study update (peek.software — EDIT ONLY, never commit)

`/case-study/marketplace-rebuild` already describes Reelvenue, anonymized.
Add, from this update:

1. **The UI-review pass** — a new section under "What the pilot harness caught":
   the build shipped green, then a full per-persona walk caught 16 defects the
   tests didn't (the 6 scanable classes above). This is *Detectable* working —
   a human/independent review pass as the second gate.
2. **The login-bounce incident** — as a concrete "caught before users" story
   (auth-session race, second-account sign-in).
3. **The lesson** — extend "LLM checking LLM is not independent verification"
   with: an independent *walk-the-product* review caught bugs no test suite was
   written to catch.

---

## Suggested order

1. A1 TD-052 + TD-054 + TD-055 (pure Semgrep rules) — fastest, testable on
   reelvenue/setdots.
2. B teardowns 052–056 (peek.software) — unblocked by A1's vulnerable/hardened
   snippets.
3. C case study — after B.
4. A1 TD-053 (Firebase rules/query cross-check) — the bigger provider lift.
5. A2 enrich TD-048.
