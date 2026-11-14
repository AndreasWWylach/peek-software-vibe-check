// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview scc provider — monolithic-file detection (file-size metric).
 *
 * scc counts lines of code per file. A file that balloons past a threshold is
 * the classic "monolithic file" smell (TD-019): UI, business logic, and data
 * access collapsed into one unreviewable blob. Offline and deterministic —
 * pure line counting, no network.
 */
import { existsSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';
import { commandAvailable, runCommand } from '../proc.mjs';
import { lookupTeardown } from '../catalog.mjs';
import { IGNORED_DIRS, isIgnoredDir } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */
/** @typedef {import('../catalog.mjs').TeardownFact} TeardownFact */

/** The teardown this provider maps to (file-size metric → monolithic file). */
const TEARDOWN_ID = 'TD-019';

/**
 * Default size threshold in total lines (matches TD-019's "500+ lines").
 * Overridable per-app via `ruleParams.maxFileLines`.
 */
const DEFAULT_MAX_FILE_LINES = 500;

/** Fallbacks when the vendored catalog does not yet carry TD-019. */
const DEFAULTS = {
  pillar: /** @type {Pillar} */ ('architecture'),
  severity: /** @type {Severity} */ ('high'),
  fixSummary:
    'Split the feature into layers — a validation schema, a service for business logic, a repository for data access, and a thin UI — so each part is testable and replaceable on its own.',
};

/** @type {Provider} */
export const sccProvider = {
  id: 'scc',
  name: 'scc (file-size metrics)',
  available: () => commandAvailable('scc'),
  // scc is language-agnostic: it counts any source file it recognises, so it
  // runs whenever the binary is present (gated only by `available`).
  applicable: () => true,
  async run(config, ctx) {
    const threshold = readThreshold(config);
    const targets = ctx.targets.filter((target) => existsSync(target));
    if (targets.length === 0) {
      ctx.log('  no existing targets — nothing to scan');
      return [];
    }

    const fact = await lookupTeardown(TEARDOWN_ID);
    /** @type {Finding[]} */
    const findings = [];
    for (const target of targets) {
      const stdout = runCommand(
        'scc',
        [
          '--by-file', '--format', 'json', '--no-complexity', '--no-cocomo', '--no-gitignore',
          '--exclude-dir', [...IGNORED_DIRS].join(','),
          target,
        ],
        { cwd: ctx.repoRoot },
      );
      for (const file of parseSccJson(stdout)) {
        // Only flag code-bearing files under the app's own source. Data files
        // (JSON, Markdown, caches) have `code === 0` and are not "monolithic
        // code"; junk dirs (node_modules, dist, …) are excluded defensively.
        if (file.code === 0) continue;
        if (isIgnoredDir(file.location)) continue;
        if (file.lines < threshold) continue;
        findings.push(toFinding(file, ctx.repoRoot, threshold, fact));
      }
    }
    return findings;
  },
};

/**
 * Read the size threshold — `ruleParams.maxFileLines` when present, else 500.
 * @param {ScanConfig} config
 * @returns {number}
 */
function readThreshold(config) {
  const value = config.ruleParams?.maxFileLines;
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return Math.floor(value);
  }
  return DEFAULT_MAX_FILE_LINES;
}

/**
 * Parse `scc --by-file --format json` output into per-file line counts.
 * @param {string} stdout
 * @returns {Array<{ location: string; lines: number; code: number }>}
 */
export function parseSccJson(stdout) {
  const parsed = JSON.parse(stdout);
  const groups = Array.isArray(parsed) ? parsed : [];
  /** @type {Array<{ location: string; lines: number; code: number }>} */
  const files = [];
  for (const group of groups) {
    const list = Array.isArray(group?.Files) ? group.Files : [];
    for (const entry of list) {
      const location = String(entry?.Location ?? '');
      if (!location) continue;
      files.push({
        location,
        lines: Number(entry?.Lines ?? 0),
        code: Number(entry?.Code ?? 0),
      });
    }
  }
  return files;
}

/**
 * Build a TD-019 finding from a file-size entry.
 * @param {{ location: string; lines: number; code: number }} file
 * @param {string} repoRoot
 * @param {number} threshold
 * @param {TeardownFact | undefined} fact — catalog facts, when vendored.
 * @returns {Finding}
 */
function toFinding(file, repoRoot, threshold, fact) {
  const repoFile = repoRelative(file.location, repoRoot);
  return {
    id: `scc:${repoFile}`,
    kind: 'teardown',
    file: repoFile,
    line: null,
    column: null,
    severity: fact?.severity ?? DEFAULTS.severity,
    pillar: fact?.pillar ?? DEFAULTS.pillar,
    teardownId: TEARDOWN_ID,
    title: `Monolithic file: ${repoFile}`,
    message: `${repoFile} is ${file.lines} lines (${file.code} of them code) — over the ${threshold}-line limit for a single file.`,
    fixSummary: fact?.fixSummary ?? DEFAULTS.fixSummary,
    source: { provider: 'scc', ruleId: 'monolithic-file' },
    dependency: null,
  };
}

/**
 * Normalize an scc `Location` to a repo-relative path (handles absolute targets).
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
