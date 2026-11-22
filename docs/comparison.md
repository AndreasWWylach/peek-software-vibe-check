## Comparison with other public available / similar repositories

**peek-software-vibe-check** goes much deeper on static architecture, multi-tenant data isolation, and multi-stack engineering quality, whereas the other three repos are lightweight, fast-setup scanners optimized for solo founders and AI-assisted quick fixes.
Because there are no independent third-party benchmark suites comparing these brand-new tools yet, the clearest way to evaluate their performance is by looking at their detection architecture, setup overhead, and blind spots.

### Side-by-Side Comparison

| Feature / Metric | peek-software-vibe-check | [Vibeship Scanner](https://github.com/vibeforge1111/vibeship-scanner) | [Vibe Scanner](https://github.com/CyprianTinasheAarons/vibe-scanner) | [Vibe-Check](https://github.com/benavlabs/vibe-check) |
|---|---|---|---|---|
| Primary Approach | Deep local SAST + architecture & tenant audit | Broad SAST + AI fix prompt generator | Lightweight Next.js / Supabase repo + URL check | Live URL probe + AI agent rules/audit prompt |
| Underlying Engines | Up to 17 providers (semgrep, osv-scanner, madge, scc, gitleaks, eslint, phpstan, bandit, gosec, etc.) | 4 tools (Opengrep, Trivy, Gitleaks, npm audit) | Pure Python custom checks (9 repo rules + URL checks) | Dependency-free Python live probe (check.py) + LLM prompts
| Setup Weight | Heavy (requires Node ≥ 22 + up to 12 external CLI binaries) | Low (web UI via GitHub OAuth or self-hosted) | Very Low (standard Python 3.10+ package) | Minimal (copy markdown files / single Python script)
| Code Privacy	100% local & offline (zero telemetry; only OSV CVE check uses network)| Web version requires repo access (public or GitHub OAuth) | 100% local read-only CLI / MCP server | 100% local / external HTTP probe |
| Live URL Scanning | No (static source & config analysis only) | No (repo-only) | Yes (checks headers, CORS, exposed files) | Yes (checks headers, exposed .env/.git, source maps)
| AI Fix Workflow | Links findings to human-written TD-XXX incident teardowns | Generates copy-pasteable "Master AI Fix Prompts" | Exposes an MCP server & Codex skill for agents | Includes [AGENTS.md](http://agents.md/) prevention rules + Claude Code skill
Maturity | Status	Early beta (0 stars; 13 golden-tested teardown rules) | Established community tool (2,000+ rulesets) | Niche/early-stage (1 star; focused on Next.js/Supabase) | Active (155 stars; updated regularly)


### Where peek-software-vibe-check Outperforms the Others

• Structural & Architectural Depth: The other three focus almost exclusively on security surface issues (leaked keys, missing auth checks, CORS). peek is the only one that checks codebase health and maintainability—using madge to catch circular dependencies, scc to flag AI-generated monolithic files, and phpstan/bandit/gosec to catch hallucinated methods or type errors.
• Automated Tenant Isolation Discovery: While Vibe Scanner checks for missing Supabase Row-Level Security (RLS), peek actively parses your Prisma schemas and SQL migrations to discover tenant boundaries and cross-checks Firestore rules against actual queries.
• True Zero-Telemetry Offline Execution: Unlike Vibeship's hosted scanner (which requires granting GitHub OAuth for private repos), peek never touches an external server except to query the open-source OSV vulnerability database.

### Where the Other Scanners Outperform peek

• Catching Production Deployment Mistakes (Vibe-Check & Vibe Scanner): Static code scanners cannot see misconfigured CDN headers, exposed .git folders on your host, or public JavaScript source maps in production. Both benavlabs/vibe-check and CyprianTinasheAarons/vibe-scanner scan your live deployed URL to catch runtime hosting flaws that peek will miss.
• Speed & Zero-Friction Onboarding: Installing 12 separate security binaries (semgrep, trivy, checkov, phpstan, etc.) via vibe-check setup takes time and disk space, even with its interactive installer. Vibe-Check and Vibe Scanner run in seconds with standard Python and zero third-party binaries.
• Turnkey AI Remediation (Vibeship & Vibe-Check): peek is built for engineers who want evidence and architectural teardowns to audit code manually or hand off to a consultancy. If you are "vibe-fixing" with Cursor or Claude Code, Vibeship's auto-generated fix prompts and Vibe-Check's AGENTS.md guardrails integrate much faster into an AI-coding loop.

### Which One Should You Pick?

• Choose peek-software-vibe-check if you are taking an AI-built SaaS app (especially multi-tenant Node, Python, or PHP) toward real production and want a rigorous, offline engineering audit—not just a surface security pass.
• Pair it with benavlabs/vibe-check or CyprianTinasheAarons/vibe-scanner right after deploying, since a quick external URL scan will catch hosting/header misconfigurations that static source scanners cannot see.
• Choose Vibeship Scanner if you want broad rule coverage (2,000+ patterns) and instant copy-paste prompts to let Claude or Cursor patch issues for you without installing a heavy local toolchain.
If you'd like to test peek-software-vibe-check on a specific repo, share your primary language/framework and OS—I can list the exact subset of its 12 binaries you actually need to install so you can skip the rest.

---

## Enhancement opportunities (2026-11-22)

Derived from reading the other repos' READMEs (ideas only — every implementation
here is written from scratch, per the no-copying rule):

1. **Opt-in live deployment probe** — `vibe-check probe <url>`, a separate
   command so `run` stays 100% offline. The READMEs clarified the concrete
   checks worth doing: final-HTTPS transport, deployed security headers,
   wildcard CORS, cookie flags, server disclosure (`X-Powered-By`), exposed
   `/.env` / `/.git/HEAD`, public source maps, and debug/docs endpoints
   (`/debug`, `/swagger`, `/api/docs`). Safety rules worth adopting as ideas:
   read-only GET/HEAD, redirect cap, request cap, and rejecting
   localhost/private-network URLs.
2. **Rule-catalog gap list** — benavlabs' "17 most common vibe-coded
   vulnerabilities" is a useful checklist to cross our catalog against.
   Covered today: unprotected API routes (TD-032), committed secrets,
   IDOR (TD-008), frontend secrets (TD-016), SQLi (TD-033), XSS (hygiene),
   unverified webhooks (TD-050), security headers. Missing (Phase 5
   priorities): RLS (planned), SSRF (planned), CSRF, wildcard-CORS code config,
   weak password hashing, insecure file uploads, debug-endpoint exposure,
   rate-limit presence.
3. **Agent-consumable fix prompts + a Claude Code skill** — both small scanners
   ship one; ours can be richer because every finding carries a full teardown
   (`fixSummary` + hardened code link). Planned together with the
   agent-provenance work.
4. **Stack-aware onboarding** — install only the binaries the detected stack
   needs (skip phpstan for a JS-only repo, etc.).
5. **Deliberately NOT adopting** — 2,200-rule mega-rulepacks (noise over
   precision) and hosted repo scanning (upload) — both against the trust
   model.
