// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Hadolint provider — Dockerfile quality & hygiene lint.
 *
 * Hadolint is the strict, deterministic Dockerfile linter (DL3000-series rules:
 * pin image tags, pin apt/npm versions, JSON CMD, pipefail, …). It complements
 * checkov, which does Dockerfile *security* posture (non-root user, secrets);
 * Hadolint does Dockerfile *quality*. Both are runtime-infra signals, so both
 * report as **advisories** (reported, not scored) — same rationale as checkov's
 * CKV_DOCKER checks.
 *
 * `severity` here is display-only (error→high, warning→medium, info/style→low);
 * it sorts findings but never contributes to the risk score.
 */
import { readdirSync, statSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { commandAvailable, runCommandCapture } from '../proc.mjs';
import { isIgnoredDir } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */

/** Map hadolint's levels to our severity enum (display only — findings advisory). */
const HADOLINT_SEVERITY = /** @type {Record<string, Severity>} */ ({
  error: 'high',
  warning: 'medium',
  info: 'low',
  style: 'low',
});

/** @type {Provider} */
export const hadolintProvider = {
  id: 'hadolint',
  name: 'Hadolint (Dockerfile)',
  available: () => commandAvailable('hadolint'),
  applicable: () => true,
  async run(_config, ctx) {
    const dockerfiles = findDockerfiles(ctx.repoRoot, ctx.targets);
    if (dockerfiles.length === 0) {
      ctx.log('  no Dockerfiles detected — skipping');
      return [];
    }

    ctx.log(`  ${dockerfiles.length} Dockerfile(s) — linting`);
    const args = ['--format', 'json', ...dockerfiles.map((file) => join(ctx.repoRoot, file))];
    const { stdout } = runCommandCapture('hadolint', args);
    return parseHadolintJson(stdout, ctx.repoRoot);
  },
};

/**
 * Parse `hadolint --format json` into findings.
 * @param {string} stdout
 * @param {string} repoRoot
 * @returns {Finding[]}
 */
export function parseHadolintJson(stdout, repoRoot) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.map((result) => toFinding(result, repoRoot));
}

/**
 * Convert one hadolint result into a finding.
 * @param {Record<string, any>} result
 * @param {string} repoRoot
 * @returns {Finding}
 */
function toFinding(result, repoRoot) {
  const code = String(result.code ?? 'hadolint');
  const severity = /** @type {Severity} */ (
    HADOLINT_SEVERITY[String(result.level ?? '').toLowerCase()] ?? 'low'
  );
  const message = String(result.message ?? code);

  const absolutePath = String(result.file ?? '');
  const file = absolutePath.startsWith(repoRoot)
    ? absolutePath.slice(repoRoot.length).replace(/^[/\\]+/, '')
    : absolutePath.replace(/^[/\\]+/, '');

  const line = typeof result.line === 'number' ? /** @type {number} */ (result.line) : null;
  const column = typeof result.column === 'number' ? /** @type {number} */ (result.column) : null;

  return {
    id: `hadolint:${code}:${file}:${line ?? 0}`,
    kind: 'hygiene',
    file,
    line,
    column,
    severity,
    pillar: 'runtime',
    teardownId: null,
    // Hadolint's message is both the description and the actionable guidance.
    title: message,
    message: null,
    fixSummary: null,
    source: { provider: 'hadolint', ruleId: code },
    dependency: null,
    // Dockerfile quality is a policy/quality signal, not a proven code defect.
    advisory: true,
  };
}

/**
 * Collect repo-relative Dockerfile paths under targets + repo root.
 * @param {string} repoRoot
 * @param {string[]} targets — absolute target paths.
 * @returns {string[]} repo-relative paths (deduplicated).
 */
export function findDockerfiles(repoRoot, targets) {
  /** @type {string[]} */
  const out = [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const target of targets) walk(target, repoRoot, out, seen);
  // Root-level Dockerfiles live outside scan targets.
  /** @type {string[]} */
  let entries = [];
  try {
    entries = readdirSync(repoRoot);
  } catch {
    // unreadable root — no root-level Dockerfiles to add
  }
  for (const name of entries) {
    if (isDockerfileName(name)) out.push(name);
  }
  return out;
}

/**
 * Is this basename a Dockerfile (`Dockerfile` or `Dockerfile.<suffix>`)?
 * @param {string} base
 * @returns {boolean}
 */
function isDockerfileName(base) {
  return base === 'Dockerfile' || base.startsWith('Dockerfile.');
}

/**
 * Walk a directory (or single file target), collecting Dockerfiles.
 * @param {string} dir
 * @param {string} repoRoot
 * @param {string[]} out
 * @param {Set<string>} seen
 */
function walk(dir, repoRoot, out, seen) {
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    return;
  }
  if (stat.isFile()) {
    const repoFile = toRepoFile(dir, repoRoot);
    const base = repoFile.split(/[\\/]/).pop() ?? '';
    if (!seen.has(repoFile) && isDockerfileName(base)) {
      seen.add(repoFile);
      out.push(repoFile);
    }
    return;
  }
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (isIgnoredDir(entry.name)) continue;
      walk(abs, repoRoot, out, seen);
    } else if (entry.isFile() && isDockerfileName(entry.name)) {
      const repoFile = toRepoFile(abs, repoRoot);
      if (isIgnoredDir(repoFile)) continue;
      if (!seen.has(repoFile)) {
        seen.add(repoFile);
        out.push(repoFile);
      }
    }
  }
}

/**
 * Normalize an absolute path to a repo-relative one.
 * @param {string} location
 * @param {string} repoRoot
 * @returns {string}
 */
function toRepoFile(location, repoRoot) {
  if (isAbsolute(location)) {
    return relative(repoRoot, location).replace(/^[/\\]+/, '');
  }
  return location.replace(/^[/\\]+/, '');
}
