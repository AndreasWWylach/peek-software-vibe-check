// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Agent-log claim cross-check — the closing loop of the
 * remediation workflow.
 *
 * The fix-prompt companion (`FIX-PROMPTS.md`) and the bundled Claude skill
 * instruct agents to record their results in the team's run log:
 *
 *   - [x] TD-033 — fixed in src/db/users.ts
 *   - [ ] TD-019 — false positive, <why>
 *
 * This module parses those claims from the agent-workflow log files named in
 * `ruleParams.agentLogPatterns` and verifies each `- [x]` claim against the
 * current scan: a claim is CONTRADICTED when the scanner still reports the
 * same teardown in the same file. The agent's claim is checked by a
 * deterministic re-run — never taken on faith.
 *
 * Honesty first: a teardown that is not part of this scan's enabled rules is
 * reported as "not re-checkable", never as "holds".
 */

/** A parsed claim line from an agent-workflow log.
 * @typedef {Object} AgentClaim
 * @property {string} teardownId — `TD-xxx`.
 * @property {string | null} file — the file the agent claims to have fixed, when named.
 * @property {'fixed' | 'left'} intent — `- [x]` (claimed fixed) or `- [ ]` (declared unfixed/false positive).
 * @property {string} detail — the free text after the dash.
 */

/** A verified claim (the report shape).
 * @typedef {Object} VerifiedClaim
 * @property {string} teardownId
 * @property {string | null} file
 * @property {'holds' | 'contradicted' | 'acknowledged' | 'not-checkable'} status
 * @property {string} detail
 */

/** A claim line: `- [x] TD-xxx — …` / `- [ ] TD-xxx — …` (em- or ascii dash). */
const CLAIM_RE = /^\s*[-*]\s+\[(x|X| )\]\s+(TD-\d{3})\b\s*[—-]\s*(.*)$/;

/** `fixed in <path>` — the file the agent claims to have fixed. */
const FIXED_IN_RE = /\bfixed\s+in\s+(['"]?)([^\s'"]+)\1/i;

/** Never trust a log file beyond a sane line count. */
const MAX_CLAIMS_PER_FILE = 200;
const MAX_FILE_BYTES = 500_000;

/**
 * Parse claim lines from agent-log content. Only the exact checklist shape is
 * recognized — free-form prose is never inferred as a claim.
 * @param {string} content
 * @returns {AgentClaim[]}
 */
export function parseFixClaims(content) {
  /** @type {AgentClaim[]} */
  const claims = [];
  for (const line of content.slice(0, MAX_FILE_BYTES).split(/\r?\n/)) {
    if (claims.length >= MAX_CLAIMS_PER_FILE) break;
    const match = CLAIM_RE.exec(line);
    if (!match) continue;
    const checked = match[1].toLowerCase() === 'x';
    const detail = match[3].trim();
    const fileMatch = FIXED_IN_RE.exec(detail);
    claims.push({
      teardownId: match[2],
      file: fileMatch ? fileMatch[2] : null,
      intent: checked ? 'fixed' : 'left',
      detail,
    });
  }
  return claims;
}

/**
 * Verify claims against the current scan's findings + enabled rules.
 *
 * - `- [x]` claim + same teardown still reported in the same file → `contradicted`.
 * - `- [x]` claim + no such finding → `holds` (when the TD was scanned).
 * - `- [x]` claim + TD not in `enabledRules` → `not-checkable`.
 * - `- [ ]` (declared unfixed/false positive) → `acknowledged` — the agent
 *   already said it is not fixed, so there is nothing to contradict.
 *
 * @param {import('./types.mjs').Finding[]} findings
 * @param {string[]} enabledRules
 * @param {AgentClaim[]} claims
 * @returns {VerifiedClaim[]} sorted by (teardownId, file).
 */
export function verifyFixClaims(findings, enabledRules, claims) {
  const enabled = new Set(enabledRules);
  /** @type {VerifiedClaim[]} */
  const verified = [];
  for (const claim of claims) {
    // `intent` is an internal parsing detail — never emitted to the report.
    const { intent, ...claimFields } = claim;
    if (intent === 'left') {
      verified.push({ ...claimFields, status: 'acknowledged' });
      continue;
    }
    if (!enabled.has(claim.teardownId)) {
      verified.push({ ...claimFields, status: 'not-checkable' });
      continue;
    }
    const stillReported = claim.file
      ? findings.some((f) => f.teardownId === claim.teardownId && f.file === claim.file)
      : findings.some((f) => f.teardownId === claim.teardownId);
    verified.push({
      ...claimFields,
      status: stillReported ? 'contradicted' : 'holds',
    });
  }
  return verified.sort((a, b) =>
    a.teardownId === b.teardownId
      ? (a.file ?? '').localeCompare(b.file ?? '')
      : a.teardownId.localeCompare(b.teardownId),
  );
}
