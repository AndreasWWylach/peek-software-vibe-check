---
name: vibe-check
description: Remediate vibe-check deep-scan findings. Use when the user asks to fix scan findings, work through FIX-PROMPTS.md, lower the risk score, or verify that reported issues (teardowns, hygiene findings, dependency CVEs) are resolved. Reads peek-report.json + FIX-PROMPTS.md, fixes one finding group at a time, and re-runs the scan to prove each fix.
---

# vibe-check remediation

You fix findings from the vibe-check deep-scan engine (peek.software). Every
finding is evidence-based: a machine-readable `peek-report.json` plus a
human-readable `AUDIT-REPORT.md`, and usually a `FIX-PROMPTS.md` with one
copy-paste prompt per finding group.

## Inputs

1. `peek-report.json` — the authoritative machine report (findings carry
   `teardownId`, `file`, `line`, `severity`, `message`, `fixSummary`).
2. `FIX-PROMPTS.md` — generated next to the report; work through its sections
   in order. If it is missing, run `vibe-check fix-prompts --report <path>`.
3. `catalog/teardowns.json` — vendored teardown facts (fixSummary per TD).
4. Golden fixtures — `tests/golden/fixtures/<td-lowercase>/` in the engine repo
   contain the TD's verified hardened code when the engine repo is checked out.

## Workflow

1. **Locate the report** (`peek-report.json`) and the config the scan used.
2. **Work one group at a time** — follow the order in `FIX-PROMPTS.md`
   (critical first). For each group:
   - Open the listed file(s) and read the surrounding code.
   - Apply the fix per the group's `fixSummary` (and the teardown's hardened
     example when available). Never copy a fix blindly — adapt it to the
     actual code.
   - Do not change unrelated behavior; keep the public API/UX identical.
3. **Prove every fix** — after each group, re-run the scan the user used, e.g.
   `vibe-check run --config <config> --out <dir>`, and confirm the specific
   finding id(s) for that group are gone from `peek-report.json`.
4. **When done**: run the project's own test suite, then report the before/after
   risk score.

## Recording the result

Append a section to the team's run log (`docs/BUILD_RUN_<date>.md`, or the
files the scan listed under "Agent Provenance"):

```markdown
## vibe-check remediation — <date>

- [x] TD-033 — fixed in src/db/users.ts
- [ ] TD-019 — false positive, <why it was left>
```

Use `- [x] … — fixed in <file>` for fixes and `- [ ] … — false positive, <why>`
for findings you intentionally left — the next scan re-verifies every claim
against the code and contradicts claims that do not hold.

## Honesty rules

- Never claim a finding is fixed without re-running the scan and seeing it
  gone. "It compiles" is not verification.
- If a finding is a false positive, say so in the log instead of changing code.
- Never print secret values found by the scan; say they must be rotated.
