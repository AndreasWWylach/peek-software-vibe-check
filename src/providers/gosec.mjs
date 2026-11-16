// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview gosec provider — Go security SAST.
 *
 * gosec gives Go the dataflow/taint checks our Semgrep pattern rules lack
 * (command injection via os/exec, SQL injection via database/sql, hardcoded
 * credentials). Language-gated: applies only when `go` is in the config's
 * detected languages, so mixed repos get gosec only on their Go module.
 *
 * Finding mapping: G201/G202/G701 (SQL) → TD-033, G204/G702 (command) → TD-042,
 * G101 (hardcoded creds) → TD-016 — so they dedup + corroborate with
 * semgrep/gitleaks by teardownId+file:line. Everything else is hygiene advisory.
 *
 * Caveat (verified against gosec 2.30.0): the SQL rules (G201/G202/G701) are
 * **taint-driven** — they only fire when the input traces back to a real source
 * (`os.Args`, `http.Request`, …), so a bare function parameter is *not* flagged.
 * G101 hardcoded-credential detection is name-pattern based and misses some
 * secrets — gitleaks/trivy cover TD-016 on Go in that case.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { commandAvailable, runCommandCapture } from '../proc.mjs';
import { enrichTeardowns } from '../catalog.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */

/** Map gosec severity strings to our shared enum. */
const GOSEC_SEVERITY = /** @type {Record<string, Severity>} */ ({
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
});

/** gosec rule id → teardown id (for dedup + corroboration). */
const GOSEC_TD_MAP = /** @type {Record<string, string>} */ ({
  G201: 'TD-033', // SQL injection (string building)
  G202: 'TD-033', // SQL string concatenation
  G701: 'TD-033', // SQL injection via taint analysis
  G204: 'TD-042', // subprocess launched with variable
  G702: 'TD-042', // command injection via taint analysis
  G101: 'TD-016', // hardcoded credentials
});

/** @type {Provider} */
export const gosecProvider = {
  id: 'gosec',
  name: 'gosec (Go)',
  available: () => commandAvailable('gosec'),
  applicable: (config) => hasLanguage(config, 'go'),
  async run(_config, ctx) {
    // gosec needs a Go module to analyze (`./...` resolves from the module
    // root). Run from the repo root — Go modules in subdirs are not yet
    // supported (documented limitation).
    if (!existsSync(join(ctx.repoRoot, 'go.mod')) && !existsSync(join(ctx.repoRoot, 'go.sum'))) {
      ctx.log('  no go.mod/go.sum at repo root — skipping');
      return [];
    }
    const { stdout } = runCommandCapture('gosec', ['-fmt', 'json', '-quiet', './...'], { cwd: ctx.repoRoot });
    return enrichTeardowns(parseGosecJson(stdout, ctx.repoRoot));
  },
};

/**
 * Parse `gosec -fmt json` into findings.
 * @param {string} stdout
 * @param {string} repoRoot
 * @returns {Finding[]}
 */
export function parseGosecJson(stdout, repoRoot) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  const issues = /** @type {Array<Record<string, any>> | undefined} */ (parsed?.Issues);
  if (!Array.isArray(issues)) return [];
  return issues.map((issue) => toFinding(issue, repoRoot));
}

/**
 * Convert one gosec issue into a finding.
 * @param {Record<string, any>} issue
 * @param {string} repoRoot
 * @returns {Finding}
 */
function toFinding(issue, repoRoot) {
  const ruleId = String(issue.rule_id ?? 'gosec');
  const severity = /** @type {Severity} */ (
    GOSEC_SEVERITY[String(issue.severity ?? '').toUpperCase()] ?? 'low'
  );
  const title = String(issue.details ?? ruleId);
  const line = Number.parseInt(String(issue.line ?? ''), 10);
  const lineNumber = Number.isFinite(line) ? line : null;

  const absolutePath = String(issue.file ?? '');
  const file = absolutePath.startsWith(repoRoot)
    ? absolutePath.slice(repoRoot.length).replace(/^[/\\]+/, '')
    : absolutePath.replace(/^[/\\]+/, '');

  const teardownId = GOSEC_TD_MAP[ruleId] ?? null;
  const kind = teardownId ? 'teardown' : 'hygiene';

  return {
    id: `gosec:${ruleId}:${file}:${lineNumber ?? 0}`,
    kind,
    file,
    line: lineNumber,
    column: null,
    severity,
    pillar: 'security',
    teardownId,
    title,
    message: teardownId ? null : `${title} (confidence: ${String(issue.confidence ?? '?')})`,
    fixSummary: null,
    source: { provider: 'gosec', ruleId },
    dependency: null,
    advisory: !teardownId,
  };
}

/**
 * Does the config list the given language (case-insensitive)?
 * @param {ScanConfig} config
 * @param {string} language
 * @returns {boolean}
 */
function hasLanguage(config, language) {
  return config.languages.some((lang) => lang.toLowerCase() === language);
}
