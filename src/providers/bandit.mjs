// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Bandit provider — Python security SAST.
 *
 * Bandit gives the dataflow/pattern checks for Python that our Semgrep
 * pattern-mode rules can't fully cover (shell=True subprocess, SQL string
 * concat, pickle/eval, hardcoded passwords). It is **language-gated**: the
 * provider only applies when `python` is in the config's detected languages,
 * so mixed repos (TS/JS + Python helpers) get Bandit only on their Python.
 *
 * Finding mapping: known Bandit ids map to teardowns (B608 → TD-033 SQLi,
 * B60x shell → TD-042 command injection, B105/106 → TD-016 hardcoded secret)
 * so they dedup + corroborate with semgrep/gitleaks by teardownId+file:line;
 * everything else is a hygiene advisory.
 */
import { existsSync } from 'node:fs';
import { commandAvailable, runCommandCapture } from '../proc.mjs';
import { enrichTeardowns } from '../catalog.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */

/** Map Bandit severity strings to our shared enum. */
const BANDIT_SEVERITY = /** @type {Record<string, Severity>} */ ({
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
});

/** Bandit test id → teardown id (for dedup + corroboration with semgrep/gitleaks). */
const BANDIT_TD_MAP = /** @type {Record<string, string>} */ ({
  B608: 'TD-033', // SQL injection through string building
  B602: 'TD-042', // subprocess with shell=True
  B603: 'TD-042',
  B604: 'TD-042',
  B605: 'TD-042', // os.system / shell process
  B606: 'TD-042',
  B607: 'TD-042',
  B105: 'TD-016', // hardcoded password string
  B106: 'TD-016',
});

/** Bandit ids that are pure noise (assert usage, try/except-pass) — skipped. */
const BANDIT_IGNORE_IDS = new Set(['B101', 'B110']);

/** @type {Provider} */
export const banditProvider = {
  id: 'bandit',
  name: 'Bandit (Python)',
  available: () => commandAvailable('bandit'),
  applicable: (config) => hasLanguage(config, 'python'),
  async run(config, ctx) {
    const targets = ctx.targets.filter((target) => existsSync(target));
    if (targets.length === 0) {
      ctx.log('  no existing targets — skipping');
      return [];
    }
    const args = ['-r', ...targets, '-f', 'json', '-q'];
    const { stdout } = runCommandCapture('bandit', args, { cwd: ctx.repoRoot });
    return enrichTeardowns(parseBanditJson(stdout, ctx.repoRoot));
  },
};

/**
 * Parse `bandit -f json` into findings.
 * @param {string} stdout
 * @param {string} repoRoot
 * @returns {Finding[]}
 */
export function parseBanditJson(stdout, repoRoot) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  const results = /** @type {Array<Record<string, any>> | undefined} */ (parsed?.results);
  if (!Array.isArray(results)) return [];
  const findings = [];
  for (const result of results) {
    const finding = toFinding(result, repoRoot);
    if (finding) findings.push(finding);
  }
  return findings;
}

/**
 * Convert one bandit result into a finding (or null when the id is ignored).
 * @param {Record<string, any>} result
 * @param {string} repoRoot
 * @returns {Finding | null}
 */
function toFinding(result, repoRoot) {
  const testId = String(result.test_id ?? 'bandit');
  if (BANDIT_IGNORE_IDS.has(testId)) return null;
  const severity = /** @type {Severity} */ (
    BANDIT_SEVERITY[String(result.issue_severity ?? '').toUpperCase()] ?? 'low'
  );
  const title = String(result.issue_text ?? testId);
  const line = typeof result.line_number === 'number' ? /** @type {number} */ (result.line_number) : null;

  const absolutePath = String(result.filename ?? '');
  const file = absolutePath.startsWith(repoRoot)
    ? absolutePath.slice(repoRoot.length).replace(/^[/\\]+/, '')
    : absolutePath.replace(/^[/\\]+/, '');

  const teardownId = BANDIT_TD_MAP[testId] ?? null;
  const kind = teardownId ? 'teardown' : 'hygiene';

  return {
    id: `bandit:${testId}:${file}:${line ?? 0}`,
    kind,
    file,
    line,
    column: null,
    severity,
    pillar: 'security',
    teardownId,
    title,
    message: teardownId ? null : `${title} (confidence: ${String(result.issue_confidence ?? '?')})`,
    fixSummary: null,
    source: { provider: 'bandit', ruleId: testId },
    dependency: null,
    // Non-teardown Bandit findings are heuristic quality signals, not defects.
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
