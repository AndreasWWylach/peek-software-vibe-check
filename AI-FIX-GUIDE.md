# AI Fix Guide — vibe-check

This file teaches **any** AI coding agent (Claude Code, Cursor, Codex,
aider, OpenCode with DeepSeek, …) how to fix a vibe-check scan report. It is
the harness-neutral twin of the Claude-Code skill in `skills/vibe-check/`.

## How to use

The scan wrote three files into one directory:

- `AUDIT-REPORT.md` — the human report (risk score, findings, advisories).
- `peek-report.json` — the machine report (the authoritative source).
- `FIX-PROMPTS.md` — one copy-paste remediation prompt per finding group.

Give the agent `FIX-PROMPTS.md` and say: *"Fix these findings one section at a
time, and re-run the scan after each fix to verify."* If `FIX-PROMPTS.md` is
missing, regenerate it without re-scanning:

```bash
vibe-check fix-prompts --report peek-report.json
```

## The loop

1. **Read** the evidence in the prompt (file, line, message, `fixSummary`).
2. **Fix** every listed location, then search the codebase for the same
   pattern and fix those too. Do not change unrelated behavior.
3. **Verify** — re-run the exact scan that produced the report:
   `vibe-check run --config <config> --out <dir>` and confirm the finding is
   gone from the new `peek-report.json`. A fix that still shows up is not a fix.
4. **Log** the result in the team's run log (`docs/BUILD_RUN_<date>.md`):

   ```markdown
   - [x] TD-033 — fixed in src/db/users.ts
   - [ ] TD-019 — false positive, <why>
   ```

   `- [x] … fixed in <file>` for fixes, `- [ ] … false positive, <why>` for
   findings intentionally left — the next scan re-verifies each claim against
   the code and contradicts claims that do not hold.

## Why this works where plain prompts don't

Every prompt is generated **from the actual finding** — never generic advice —
and every finding is backed by a teardown with a known-good fix. The scanner
closes the loop: the agent's claim is checked by a deterministic re-run, not by
the agent's own confidence.
