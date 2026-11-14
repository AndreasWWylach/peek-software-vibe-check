Vibe-coded codebases—projects built rapidly via AI prompts in tools like Cursor, Claude Code, or Windsurf—tend to suffer from predictable shortcuts, hallucinated patterns, and skipped architectural guardrails. While Semgrep’s built-in --config auto rules catch classic flaws like SQL injection, security engineers and developers recommend writing custom Semgrep rules to catch the specific blind spots AI models introduce. [1] (https://semgrep.dev/events/secure-vibe-coding-real-time-ai-guardrails-with-semgrep-mcp/), [2] (https://www.sitepoint.com/vibe-coded-app-security-audit-playbook/), [3] (https://zapier.com/blog/vibe-coding-security/), [4] (https://addcommitpush.io/blog/the-rules-of-vibe-coding)

1. Security & Access Control Shortcuts

AI assistants prioritize making features "just work," which frequently leads to bypassed authentication or overly permissive defaults. [1] (https://semgrep.dev/events/secure-vibe-coding-real-time-ai-guardrails-with-semgrep-mcp/)
• Unprotected Mutating Routes. Write rules to flag any POST, PUT, or DELETE API route handler that lacks an explicit authentication or authorization middleware wrapper. [1] (https://addcommitpush.io/blog/the-rules-of-vibe-coding)
• Permissive CORS and Debug Flags. Create rules to block Access-Control-Allow-Origin: * or framework debug flags (DEBUG = True, app.run(debug=True)) that LLMs often leave enabled for local testing. [1] (https://www.youtube.com/watch?v=e432_8fn_3o&t=1481)
• Hardcoded Secrets & Fallback Keys. While default rules catch standard API keys, custom rules can catch AI-generated fallback strings like process.env.JWT_SECRET || "super-secret-dev-key". [1] (https://zapier.com/blog/vibe-coding-security/)
• Missing Input Validation Schemas. Enforce that every incoming request body or query parameter passes through a chosen validator (such as Zod or Pydantic) before touching database logic. [1] (https://github.com/obviousworks/vibe-coding-ai-rules/blob/main/docs/best-practices.md)

2. LLM & AI-Integration Anti-Patterns

Because vibe-coded apps frequently integrate AI features themselves, Semgrep offers a dedicated p/ai-best-practices ruleset, which can be extended with custom checks: [1] (https://semgrep.dev/blog/2026/security-skills-ai-agents/), [2] (https://github.com/semgrep/ai-best-practices)
• Unbounded LLM Token / Cost Loops. Flag LLM API calls inside loops or endpoints that lack max_tokens limits or rate-limiting middleware.
• Unsanitized Prompt Interpolation. Detect user input being concatenated directly into system prompts without delimiters or sanitization, preventing prompt injection.
• Unapproved Model or Provider Usage. Restrict code from importing shadow AI SDKs or unauthorized model endpoints outside the approved wrapper. [1] (https://semgrep.dev/products/product-updates/detect-risks-in-ai-generated-code-with-semgrep-guardian/), [2] (https://www.youtube.com/shorts/AI4fpByyUZw)

3. Architectural & Code-Quality Drift

When prompting iteratively, AI models often duplicate logic or break project structure instead of reusing existing helpers. [1] (https://addcommitpush.io/blog/the-rules-of-vibe-coding)
• Direct Database or Fetch Calls in UI Components. Enforce separation of concerns by flagging raw fetch(), axios, or database queries inside frontend UI folders so the AI uses the centralized API client.
• Raw Styling Instead of Design Tokens. Flag hardcoded hex colors (e.g., #3b82f6) or arbitrary pixel values in components to force the AI to use theme variables or Tailwind tokens.
• Swallowed Errors and Empty Catch Blocks. LLMs frequently silence errors to avoid crashes; write a rule banning empty catch (e) {} blocks or bare except: pass statements.
• Mock Data Left in Production Paths. Flag placeholder arrays, TODO comments, or mock variable prefixes outside of __tests__ directories. [1] (https://addcommitpush.io/blog/the-rules-of-vibe-coding)

Pro Tip: Close the Loop with MCP

To prevent the AI from writing these patterns in the first place, connect the Semgrep MCP Server (or Semgrep Guardian) to the AI editor. Add an instruction in .cursorrules or CLAUDE.md file telling the agent to run custom Semgrep rules after every edit and fix any findings before finishing. [1] (https://semgrep.dev/blog/2026/introducing-semgrep-guardian-real-time-security-for-ai-written-code/), [2] (https://semgrep.dev/blog/2025/giving-appsec-a-seat-at-the-vibe-coding-table/), [3] (https://charlesjones.dev/blog/semgrep-ai-assisted-development-security-scanning)

---

Example: Nodejs

For a vibe-coded Node.js SaaS codebase (typically Express, Fastify, or Next.js API routes with Prisma/Drizzle and Stripe), AI assistants frequently introduce multi-tenant data leaks, unauthenticated endpoints, and silent error handling.
Below is a ready-to-use .semgrep.yml file containing custom rules tailored specifically to catch those Node.js SaaS shortcuts.

Custom .semgrep.yml for a Node.js SaaS

Save this file in the root of the repository and run semgrep scan --config .semgrep.yml.
yaml
rules:
  # 1. Catch AI fallback secrets (e.g., process.env.JWT_SECRET || "dev-secret")
  - id: nodejs-saas-hardcoded-env-fallback
    patterns:
      - pattern: process.env.$VAR || "$FALLBACK"
      - metavariable-regex:
          metavariable: $VAR
          regex: .*(SECRET|KEY|TOKEN|PASSWORD|AUTH|STRIPE|WEBHOOK).*
    message: >
      Avoid hardcoded fallback strings for sensitive environment variable $VAR.
      Fail fast at startup if required secrets are missing.
    languages: [javascript, typescript]
    severity: ERROR

  # 2. Catch multi-tenant IDOR leaks in Prisma queries (missing tenant/org filter)
  - id: prisma-missing-tenant-scope
    patterns:
      - pattern: prisma.$MODEL.$METHOD({ where: { ... } })
      - pattern-not: prisma.$MODEL.$METHOD({ where: { organizationId: ..., ... } })
      - pattern-not: prisma.$MODEL.$METHOD({ where: { tenantId: ..., ... } })
      - pattern-not: prisma.$MODEL.$METHOD({ where: { userId: ..., ... } })
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(findMany|findFirst|update|updateMany|delete|deleteMany)$
    message: >
      Database query on prisma.$MODEL.$METHOD lacks an explicit tenant scope
      (organizationId, tenantId, or userId). This can expose data across SaaS tenants.
    languages: [javascript, typescript]
    severity: ERROR

  # 3. Catch Express mutating routes missing auth middleware
  - id: express-unauthenticated-mutation
    patterns:
      - pattern: $APP.$METHOD($ROUTE, $HANDLER)
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(post|put|patch|delete)$
      - pattern-not: $APP.$METHOD("/api/webhooks/...", ...)
      - pattern-not: $APP.$METHOD("/api/auth/...", ...)
    message: >
      Mutating route $METHOD $ROUTE has only one handler and appears to skip
      authentication middleware (e.g., requireAuth).
    languages: [javascript, typescript]
    severity: WARNING

  # 4. Catch Stripe webhooks missing signature verification
  - id: stripe-webhook-missing-construct-event
    patterns:
      - pattern-inside: |
          $APP.post($ROUTE, async ($REQ, $RES) => { ... })
      - metavariable-regex:
          metavariable: $ROUTE
          regex: .*stripe.*
      - pattern-not-inside: |
          $APP.post($ROUTE, async ($REQ, $RES) => {
            ...
            stripe.webhooks.constructEvent(...)
            ...
          })
    message: >
      Stripe webhook route must verify the request signature using
      stripe.webhooks.constructEvent() before processing events.
    languages: [javascript, typescript]
    severity: ERROR

  # 5. Catch AI-generated empty catch blocks that silently swallow errors
  - id: no-swallowed-errors
    patterns:
      - pattern: |
          try {
            ...
          } catch ($ERR) {
          }
    message: >
      Empty catch block detected. Log the error or pass it to an error handler
      instead of silently swallowing failures.
    languages: [javascript, typescript]
    severity: WARNING

Key Risks These Rules Prevent

• Cross-Tenant Data Leaks (Rule 2). When prompted to "add an endpoint to update a project," LLMs routinely write prisma.project.update({ where: { id } }) without checking if the project belongs to the caller's organization.
• Spoofed Billing Events (Rule 4). AI tools often mock Stripe webhook handlers by trusting req.body directly instead of validating the stripe-signature header, allowing attackers to forge checkout.session.completed payloads.
• Silent Production Failures (Rule 5). Vibe-coded error handling frequently wraps async calls in try { ... } catch (e) {} to stop crashes during demos, hiding broken database or third-party API calls in production.

Next Steps for a possible Workflow

1. Combine with Built-In Rules. Run semgrep scan --config auto --config .semgrep.yml so it's possible to get both general Node.js security rules and custom SaaS guardrails in one pass.
2. Enforce via AI Rules. Add a line to .cursorrules or CLAUDE.md file instructing the AI assistant: "Before completing any task, run semgrep scan --config .semgrep.yml and resolve all errors."


Combining MCP (local authoring-time feedback) with CI/CD (automated pull-request gates) gives a two-layer safety net for vibe-coded projects. The AI agent catches and fixes its own mistakes while writing code, and GitHub Actions guarantees nothing slips into main if a check is skipped. [1] (https://semgrep.dev/blog/2022/integrating-semgrep-with-ci/), [2] (https://docs.semgrep.dev/semgrep-guardian/overview)

Layer 1: Semgrep MCP Server (Real-Time AI Guardrails)

The official Semgrep MCP Server exposes Semgrep as a native tool to AI coding assistants like Cursor and Claude Code. Instead of waiting until testing the app, the AI scans its own generated code and auto-fixes findings immediately. [1] (https://github.com/semgrep/mcp), [2] (https://docs.semgrep.dev/semgrep-guardian/overview), [3] (https://github.com/semgrep/semgrep/blob/develop/cli/src/semgrep/mcp/README.md)

Option A: Cursor Setup (Local CLI + Hooks)

1. Install Semgrep locally if not already (brew install semgrep or pip install semgrep).
2. Register the MCP server by creating or updating .cursor/mcp.json in the project root:json
{
  "mcpServers": {
    "semgrep": {
      "command": "semgrep",
      "args": ["mcp"]
    }
  }
}

3. Instruct the agent to use the defined rules. Add a rule file at .cursor/rules/security.mdc so Cursor always runs the custom SaaS rules after generating code: [1] (https://www.linkedin.com/posts/daghanaltas_we-made-semgrep-mcp-even-simpler-ready-in-activity-7375001760777560064-DEak), [2] (https://github.com/semgrep/mcp), [3] (https://github.com/semgrep/semgrep/blob/develop/cli/src/semgrep/mcp/README.md), [4] (https://charlesjones.dev/blog/semgrep-ai-assisted-development-security-scanning)
markdown
---
description: Security and SaaS architecture checks
globs: ["**/*.ts", "**/*.js"]
alwaysApply: true
---
After creating or editing code, call the Semgrep MCP `semgrep_scan` tool using the local `.semgrep.yml` config file. Fix any ERROR or WARNING findings before finishing the response.

Option B: Claude Code Setup (Plugin or CLI)

Semgrep provides a native plugin called Semgrep Guardian that bundles the MCP server and automatic post-edit hooks. [1] (https://docs.semgrep.dev/semgrep-guardian/overview)
• Via Claude Code Plugin Marketplace: Open claude in a terminal, run /plugin, search for Semgrep, and install it. Then run /setup-semgrep-plugin to finish setup.
• Via Local MCP Config: Alternatively, add the local server directly to the project's .mcp.json: [1] (https://github.com/semgrep/semgrep/blob/develop/cli/src/semgrep/mcp/README.md)
json
{
  "mcpServers": {
    "semgrep": {
      "command": "semgrep",
      "args": ["mcp"]
    }
  }
}

Layer 2: CI/CD Enforcement (GitHub Actions)

Even with MCP active, AI agents can sometimes ignore instructions or edit files outside an active session. A GitHub Actions workflow acts as a hard merge gate. [1] (https://appsec.guide/docs/static-analysis/semgrep/continuous-integration/), [2] (https://semgrep.dev/blog/2022/integrating-semgrep-with-ci/)
Create .github/workflows/semgrep.yml in the repository: [1] (https://dev.to/r3d_cr0wn/applying-semgrep-sast-to-any-application-3h15)
yaml
name: Semgrep Security & SaaS Guardrails

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  semgrep:
    name: Semgrep Scan
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Semgrep with Built-In & Custom SaaS Rules
        run: |
          semgrep scan \
            --config auto \
            --config .semgrep.yml \
            --error \
            --metrics=off

Why This Workflow Works Well for SaaS Teams

• Zero Cloud Account Required. Using the official semgrep/semgrep Docker container runs the open-source engine directly on GitHub's runner with no external tokens needed. [1] (https://github.com/j3ssie/sample-semgrep-ci), [2] (https://docs.semgrep.dev/deployment/oss-deployment)
• Hard Merge Blocking (--error). The --error flag forces the GitHub check to fail (exit code 1) whenever any rule with severity: ERROR triggers—such as a missing tenantId in Prisma or an unverified Stripe webhook.
• Fast Execution. Because Semgrep does not need to run npm install or compile TypeScript, the entire job typically finishes in 15 to 30 seconds.
• Branch Protection. Once the workflow runs once, go to GitHub Repo Settings → Branches → Branch protection rules for main and mark Semgrep Scan as a required status check.


Add SARIF reporting so Semgrep findings appear directly inline on GitHub Pull Request diffs

Adding SARIF (Static Analysis Results Interchange Format) reporting lets GitHub display Semgrep findings directly as inline annotations on the Pull Request diffs and track them under the repository's Security → Code scanning tab.

Updated GitHub Actions Workflow with SARIF

Update .github/workflows/semgrep.yml file to output a .sarif file and upload it using GitHub's official upload-sarif action:
yaml
name: Semgrep Security & SaaS Guardrails

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  semgrep:
    name: Semgrep Scan
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep

    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Semgrep with SARIF Output
        run: |
          semgrep scan \
            --config auto \
            --config .semgrep.yml \
            --sarif \
            --output semgrep.sarif \
            --error \
            --metrics=off

      - name: Upload SARIF file to GitHub
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif

Key Additions Explained

• permissions Block. Adding security-events: write grants the workflow permission to post alerts to GitHub's Code Scanning API.
• --sarif --output semgrep.sarif. Tells Semgrep to save the scan results in the standardized JSON-based SARIF format instead of only printing them to the console logs.
• if: always() on the Upload Step. Because --error causes the Semgrep step to fail whenever a vulnerability is found, if: always() ensures GitHub still uploads the semgrep.sarif file on failed runs so one can actually see the inline annotations on the PR.
• Repository Availability. GitHub Code Scanning and inline SARIF annotations work automatically on all public repositories and on private repositories with GitHub Advanced Security (or GitHub Code Security) enabled.

What It Looks Like in Practice

• Inline PR Comments. When an AI-generated PR introduces a missing tenantId filter or an empty catch block, GitHub places a warning or error box directly beneath the offending line in the Files changed tab.
• Centralized Alert Tracking. Under Security → Code scanning, one can filter open issues by rule ID (such as prisma-missing-tenant-scope), mark false positives, and track when vulnerabilities are resolved.
