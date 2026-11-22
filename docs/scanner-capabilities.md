# What the scanner can and cannot do

The scanner is a **static, evidence-based code audit**: it proves what it finds
from the repo's code, manifests, IaC files, and git history. It is **not a
runtime monitor**. This page is the honest capability map — what each of the
three LastMile roles gets from the scanner, and what stays out of static reach.

**Legend**

| Mark | Meaning |
|---|---|
| ✅ | **Shipped** — detected today (provider/rule named). |
| 🔶 | **Partial** — a real signal exists, but the bullet is only partly statically answerable. |
| 🟡 | **Planned** — on the backlog, not shipped yet. |
| ❌ | **Out of static reach** — a runtime/ops/compliance fact; the scanner would be lying to claim it. |

> **The hard rule:** if the fact only exists while the app *runs* (monitoring,
> throttling, drift, backups, load behavior, zero-downtime), the scanner cannot
> see it — and it reports "not statically verifiable" instead of guessing.

## Auditor — strong where the evidence is in code

| Bullet | Coverage |
|---|---|
| Secrets in a vault | ✅ Gitleaks + Semgrep TD-016 + Trivy secrets — *committed* secrets only; what's actually in the vault is out of reach. |
| Untrusted input sanitized | ✅ TD-033 (SQL concatenation), TD-042 (command injection), TD-057 (SSRF — direct request-to-fetch sinks); XSS (`dangerouslySetInnerHTML`) + open-redirect hygiene shipped. |
| Passwords stored safely | ✅ TD-058 (weak password hashing — MD5/SHA-1/unsalted SHA-256 flags; bcrypt/Argon2/scrypt expected). |
| CSRF protection | ✅ `csrf` provider — advisory, gated on DETECTED cookie auth (token-auth apps are immune and stay silent). |
| Dependencies you can trust | ✅ OSV-Scanner CVEs + missing-lockfile (scored) + floating versions (advisory). |
| Encrypted everywhere (headers) | ✅ Security-headers provider — CSP / HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy (advisory; a reverse proxy may set them outside the repo). |
| Auth can't be walked through | 🔶 TD-032 (unauthenticated handler) shipped; MFA/zero-trust is **config**, not code. |
| Audit & keep watching | 🔶 TD-026 (`process.env` logging) 🟡 planned; monitoring/alerting is ❌ runtime. |
| Brute force throttled | ❌ Rate limiting is runtime/config — no static truth. |
| Compliance GDPR/SOC2 | ❌ Not a code fact. |

## Architect — real signals, but "the design is good" stays judgment

| Bullet | Coverage |
|---|---|
| Least privilege in cloud | ✅ Checkov IAM wildcard checks (`Action: "*"` / `Resource: "*"`, CKV_AWS_62/63/355/…) — scored high (requires checkov). |
| Infrastructure as code | ✅ Checkov IaC misconfiguration scanning + IaC presence. |
| Architecture scales (modular) | 🔶 TD-021 (circular deps, Madge) + TD-019 (monolithic files, scc) — real signals; "modular / scales under load" is judgment. |
| Zero-downtime CI/CD | 🔶 CI-config presence only (pipeline / tests / coverage reference). |
| Repeatable environments | 🔶 Dockerfile/compose presence + Hadolint/Checkov lint — "present and linted", not "verified to work". |
| No drift / verified infra | ❌ Runtime fact. |

## Hardener — mostly out of static reach, by nature

| Bullet | Coverage |
|---|---|
| Confidence layer (tests) | ✅ Tests provider (presence + TD-017 no-assertions) + CI coverage-gate advisory. |
| Mutation/property testing | ❌ Not detected today (at best a future tool-presence signal — weak). |
| Fail gracefully / load / alerting / dashboards | ❌ "Sentry/k6/otel is installed" would only ever be a weak signal — not implemented; behavior is runtime. |
| Bills can't run away / backups / runbooks | ❌ Runtime or docs, never code. |

## What the ❌ rows mean in practice

The out-of-reach rows are **not a scanner gap to close** — they are facts only a
human (or the runtime itself) knows. The product handles them elsewhere:

- The **quiz** asks about them (self-report, e.g. throttling, backups,
  compliance posture).
- The report's **"Not Statically Verifiable"** section names what could not be
  checked, so a clean score is never mistaken for "everything ran".
- The **readiness verdict** layers in the signals the score deliberately
  excludes (CI maturity, dependency CVEs, disabled checks).

The scanner's promise is narrower and stronger than "analyse everything":
*it proves what it says, and says what it cannot prove.*

---

## The short version — for the `/scan` page

The same facts, composed as the two honest lists a user reads before they run
the scanner. Every "cannot" row is exactly where Last Mile's services take
over.

### What the scanner can do

Shipped unless marked planned — each item maps to a LastMile framework bullet.

- **Find committed secrets** — API keys and tokens in code and git history
  (Gitleaks, TD-016, Trivy). *(Auditor — secrets in a vault)*
- **Spot injection and unsafe sinks** — string-built SQL (TD-033), command
  injection (TD-042), XSS via `dangerouslySetInnerHTML`, open redirects;
  *planned:* SSRF. *(Auditor — untrusted input)*
- **Audit the dependency tree** — known CVEs (OSV), missing lockfile, floating
  versions. *(Auditor — dependencies you can trust)*
- **Check security headers** — CSP / HSTS / X-Frame-Options / Referrer-Policy /
  Permissions-Policy set in code or config. *(Auditor — encrypted everywhere)*
- **Find endpoints without auth** — unauthenticated request handlers (TD-032).
  *(Auditor — auth that can't be walked through)*
- **Verify tenant isolation** — auto-detects the tenant model from the Prisma
  schema or SQL migrations and checks queries for tenant scope (TD-008);
  cross-checks Firestore queries against the security rules.
  *(Auditor — least-privilege access)*
- **Audit cloud least-privilege** — IAM `Action: "*"` / `Resource: "*"` smells
  (Checkov). *(Architect — least privilege in the cloud)*
- **Scan infrastructure-as-code** — Terraform/CloudFormation/Kubernetes
  misconfigurations and Dockerfile lint (Checkov, Hadolint).
  *(Architect — infrastructure as code)*
- **Measure architecture cohesion** — circular dependencies (TD-021) and
  monolithic files (TD-019). *(Architect — an architecture built to scale)*
- **Check CI maturity** — pipeline / tests / coverage-gate presence.
  *(Architect — ship without the sweat; Hardener — confidence layer)*
- **Test-confidence signals** — test presence and assertion-less tests
  (TD-017). *(Hardener — a confidence layer)*
- **Catch the vibe-code failure patterns** — unverified payment webhooks
  (TD-050/051), reactive read/write loops (TD-052), silent failures into falsy
  defaults (TD-054), missing-vs-invalid webhook signatures (TD-055), uncapped
  LLM spend (TD-002). *(Hardener — fail gracefully; bills can't run away)*
- **Detect agent provenance** — official AI-tool markers plus the agent-log
  files you name. *(context for all three roles)*
- **Say what it cannot verify** — a "Not Statically Verifiable" section and a
  go-live readiness verdict, so a clean score is never mistaken for
  "everything was checked". *(the honesty layer)*
- **Planned** — SSRF sinks, `process.env` logging (TD-026), and a growing
  share of the 48-teardown catalog (Phase 5).

### What the scanner cannot do

Everything below happens while the app *runs*, or lives outside the repo. The
scanner reports the gap instead of guessing — and this is where Last Mile's
services take over:

- **Remediate anything.** The scanner finds; Last Mile fixes.
- **Runtime monitoring & alerting** — uptime, anomaly detection, real-time
  alerts, error tracking (Sentry), dashboards, centralized logs/metrics/traces.
- **Rate limiting & abuse detection** — throttling is runtime config.
- **MFA & zero-trust enforcement** — identity is configuration, not code.
- **Load & performance testing** — surviving real traffic is a runtime fact.
- **Secrets management** — moving keys into a vault and rotating them.
- **Zero-downtime deployment & rollbacks** — implementing the pipelines, not
  detecting their config files.
- **Drift detection & infrastructure verification** — reconciling live
  infrastructure against code.
- **Compliance (GDPR / SOC 2 / ISO)** — audit trails and evidence are an
  ops/legal workload.
- **Backups, restore testing & runbooks** — ops and documentation.
- **Judging design quality** — "scales", "modular", "works on my machine" are
  human judgments; the scanner only surfaces the code-level signals
  (circular deps, monolith size) that correlate with them.

The split is the business model, not a weakness: the scanner is the **objective
evidence layer** that proves where the problems are; Last Mile is the **fixing
and operating layer** that removes them. Both halves tell the truth about their
limits.
