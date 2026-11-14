// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Gitleaks provider — hardcoded-secret detection (TD-016).
 *
 * Gitleaks scans files for high-entropy secrets (API keys, tokens, credentials)
 * with far higher precision than a regex — entropy + allowlists. It is the
 * preferred tool for TD-016 over Semgrep's prefix regex (docs §7.4). Offline,
 * deterministic; the secret VALUE is never copied into a finding (the report
 * must not re-expose the secret it just found).
 */
import { existsSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';
import { commandAvailable, runCommandCapture } from '../proc.mjs';
import { lookupTeardown } from '../catalog.mjs';
import { isEnvFile, isIgnoredDir } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */
/** @typedef {import('../catalog.mjs').TeardownFact} TeardownFact */

/** The teardown this provider maps to (hardcoded API key / secret). */
const TEARDOWN_ID = 'TD-016';

/** Fallbacks when the vendored catalog does not yet carry TD-016. */
const DEFAULTS = {
  pillar: /** @type {Pillar} */ ('security'),
  severity: /** @type {Severity} */ ('critical'),
  fixSummary:
    'Move the secret to the server: use a server-only environment variable and call it from a route handler — never ship the SDK or the key to the browser.',
};

/** @type {Provider} */
export const gitleaksProvider = {
  id: 'gitleaks',
  name: 'Gitleaks (secrets)',
  available: () => commandAvailable('gitleaks'),
  // Gitleaks scans every file, not just one language — gate on `available`.
  applicable: () => true,
  async run(_config, ctx) {
    const targets = ctx.targets.filter((target) => existsSync(target));
    if (targets.length === 0) {
      ctx.log('  no existing targets — nothing to scan');
      return [];
    }

    const fact = await lookupTeardown(TEARDOWN_ID);
    /** @type {Finding[]} */
    const findings = [];
    let skipped = 0;
    for (const target of targets) {
      // `runCommandCapture` because gitleaks exits 1 when leaks are found (the
      // JSON report is still written to stdout via `--report-path -`).
      const { stdout } = runCommandCapture(
        'gitleaks',
        ['detect', '--no-git', '--source', target, '--report-format', 'json', '--report-path', '-'],
        { cwd: ctx.repoRoot },
      );
      for (const leak of parseGitleaksJson(stdout)) {
        // Skip junk dirs (node_modules, dist, …) and the local `.env` secret
        // store — the latter is not "shipped to the browser" (TD-016's
        // premise); it is the developer's own machine-local config.
        if (isIgnoredDir(leak.file) || isEnvFile(leak.file)) {
          skipped += 1;
          continue;
        }
        findings.push(toFinding(leak, ctx.repoRoot, fact));
      }
    }
    if (skipped > 0) {
      ctx.log(`  gitleaks: skipped ${skipped} leak(s) in ignored dirs / .env files`);
    }
    return findings;
  },
};

/**
 * Parse `gitleaks detect --report-format json` output — WITHOUT the secret.
 * @param {string} stdout
 * @returns {Array<{ ruleId: string; description: string; file: string; line: number }>}
 */
export function parseGitleaksJson(stdout) {
  const parsed = JSON.parse(stdout);
  const leaks = Array.isArray(parsed) ? parsed : [];
  return leaks.map((entry) => ({
    // Deliberately ignore `Secret` and `Match` — findings must never carry the
    // secret value (the report is written to disk and shared).
    ruleId: String(entry?.RuleID ?? ''),
    description: String(entry?.Description ?? ''),
    file: String(entry?.File ?? ''),
    line: Number(entry?.StartLine ?? 0),
  }));
}

/**
 * Build a TD-016 finding from a parsed leak (no secret value).
 * @param {{ ruleId: string; description: string; file: string; line: number }} leak
 * @param {string} repoRoot
 * @param {TeardownFact | undefined} fact — catalog facts, when vendored.
 * @returns {Finding}
 */
function toFinding(leak, repoRoot, fact) {
  const repoFile = repoRelative(leak.file, repoRoot);
  const line = leak.line > 0 ? leak.line : null;
  return {
    id: `gitleaks:${repoFile}:${line ?? 0}:${leak.ruleId}`,
    kind: 'teardown',
    file: repoFile,
    line,
    column: null,
    severity: fact?.severity ?? DEFAULTS.severity,
    pillar: fact?.pillar ?? DEFAULTS.pillar,
    teardownId: TEARDOWN_ID,
    title: `Hardcoded secret: ${repoFile}${line ? `:${line}` : ''}`,
    message: `${leak.ruleId} — ${leak.description}`,
    fixSummary: fact?.fixSummary ?? DEFAULTS.fixSummary,
    source: { provider: 'gitleaks', ruleId: leak.ruleId },
    dependency: null,
  };
}

/**
 * Normalize a gitleaks `File` path to a repo-relative path (handles absolute sources).
 * @param {string} location
 * @param {string} repoRoot
 * @returns {string}
 */
function repoRelative(location, repoRoot) {
  if (isAbsolute(location)) {
    return relative(repoRoot, location).replace(/^[/\\]+/, '');
  }
  return location.replace(/^[/\\]+/, '');
}
