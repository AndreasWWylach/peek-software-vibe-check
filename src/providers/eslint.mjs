// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview ESLint provider — language-native linter (QA-pillar hygiene).
 *
 * The one language-native linter from the core-v1 tier (docs §5.7). It runs a
 * small, deterministic set of core rules against JS-family files and reports
 * findings as `kind: 'hygiene'`, pillar `qa` — cheap, high-signal coverage on
 * top of the teardown rules. TypeScript + the type-aware TD-044
 * (`no-floating-promises`) are deferred to a follow-up that ships
 * typescript-eslint.
 */
import { existsSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommandCapture } from '../proc.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */

/** Absolute path to the shipped flat config (core rules only). */
const ESLINT_CONFIG = fileURLToPath(new URL('../../rules/eslint/eslint.config.mjs', import.meta.url));

/** Map ESLint severity numbers (2 = error, 1 = warning) to our enum. */
const SEVERITY = /** @type {Record<number, Severity>} */ ({
  2: 'medium',
  1: 'low',
});

/** @type {Provider} */
export const eslintProvider = {
  id: 'eslint',
  name: 'ESLint (language linter)',
  available: () => commandAvailable('eslint'),
  applicable: (config) =>
    (config.languages ?? []).some((language) => ['javascript', 'js'].includes(language)),
  async run(_config, ctx) {
    const targets = ctx.targets.filter((target) => existsSync(target));
    if (targets.length === 0) {
      ctx.log('  no existing targets — nothing to scan');
      return [];
    }

    // eslint exits 1 when errors are present (warnings-only exits 0; a
    // files-not-matched situation exits 2) — capture stdout in all cases.
    const { stdout } = runCommandCapture(
      'eslint',
      ['--config', ESLINT_CONFIG, '--format', 'json', '--no-warn-ignored', ...targets],
      { cwd: ctx.repoRoot },
    );
    return parseEslintJson(stdout).map((item) => toFinding(item, ctx.repoRoot));
  },
};

/**
 * Parse `eslint --format json` output into hygiene findings.
 * @param {string} stdout
 * @returns {Array<{ file: string; ruleId: string; severity: Severity; line: number | null; column: number | null; message: string }>}
 */
export function parseEslintJson(stdout) {
  const text = String(stdout ?? '').trim();
  if (!text) return [];

  /** @type {unknown} */
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return []; // eslint prints non-JSON errors (e.g. "no files matching") to stderr.
  }

  const results = Array.isArray(parsed) ? parsed : [];
  /** @type {Array<{ file: string; ruleId: string; severity: Severity; line: number | null; column: number | null; message: string }>} */
  const findings = [];
  for (const file of results) {
    const filePath = String(file?.filePath ?? '');
    const messages = Array.isArray(file?.messages) ? file.messages : [];
    for (const message of messages) {
      const ruleId = String(message?.ruleId ?? '');
      const severity = /** @type {Severity | undefined} */ (SEVERITY[Number(message?.severity ?? 0)]);
      if (!ruleId || !severity) continue; // skip `fatal`/parse errors (no ruleId).
      findings.push({
        file: filePath,
        ruleId,
        severity,
        line: Number(message?.line ?? 0) > 0 ? Number(message.line) : null,
        column: Number(message?.column ?? 0) > 0 ? Number(message.column) : null,
        message: String(message?.message ?? ''),
      });
    }
  }
  return findings;
}

/**
 * Build a QA hygiene finding from a parsed lint message.
 * @param {{ file: string; ruleId: string; severity: Severity; line: number | null; column: number | null; message: string }} item
 * @param {string} repoRoot
 * @returns {Finding}
 */
function toFinding(item, repoRoot) {
  const repoFile = repoRelative(item.file, repoRoot);
  return {
    id: `eslint:${repoFile}:${item.line ?? 0}:${item.ruleId}`,
    kind: 'hygiene',
    file: repoFile,
    line: item.line,
    column: item.column,
    severity: item.severity,
    pillar: 'qa',
    teardownId: null,
    title: item.message,
    message: null,
    fixSummary: null,
    source: { provider: 'eslint', ruleId: item.ruleId },
    dependency: null,
  };
}

/**
 * Normalize an eslint `filePath` to a repo-relative path.
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
