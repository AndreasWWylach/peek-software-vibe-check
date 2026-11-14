// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Engine identity + minimal semver range check.
 *
 * The engine version is read once from `package.json`; the git commit is
 * resolved lazily so the report can be pinned to a reviewable revision
 * (trust principle: "pinned releases").
 */
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** Parsed package.json (typed `any` — this is our own trusted file). */
const PKG = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

/** Engine name, as printed in reports and the CLI banner. */
export const ENGINE_NAME = 'vibe-check';

/** Engine version, read from package.json. */
export const ENGINE_VERSION = /** @type {string} */ (PKG.version);

/** Absolute path to the engine's own repo root (pins the report to a reviewable revision). */
const ENGINE_DIR = fileURLToPath(new URL('..', import.meta.url));

/**
 * Resolve the ENGINE's short git commit hash, or null when not in a git repo.
 * Pinned to the engine's own repository — the scanned app's HEAD is irrelevant
 * to reproducibility (and would confuse "which engine produced this report").
 * @returns {string | null}
 */
export function readCommit() {
  try {
    return execFileSync('git', ['-C', ENGINE_DIR, 'rev-parse', '--short', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return null;
  }
}

/** @typedef {[number, number, number]} Semver */

/**
 * Parse a `x.y.z` string into a numeric triple (missing parts → 0).
 * @param {string} version
 * @returns {Semver}
 */
function parseSemver(version) {
  const parts = version.trim().split('.');
  return [Number(parts[0] ?? 0), Number(parts[1] ?? 0), Number(parts[2] ?? 0)];
}

/**
 * Compare two semver triples: negative, zero, or positive.
 * @param {Semver} a
 * @param {Semver} b
 * @returns {number} <0 when a < b, 0 when equal, >0 when a > b.
 */
function compareSemver(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
  }
  return 0;
}

/**
 * Does `version` satisfy the config's `engine` range?
 *
 * Supports the two forms the config generator emits: `>=x.y.z` (minimum) and a
 * bare `x.y.z` (also treated as a minimum). Anything else fails the range check.
 * @param {string} range — e.g. ">=0.1.0".
 * @param {string} version — the running engine version.
 * @returns {boolean}
 */
export function satisfiesEngineRange(range, version) {
  const trimmed = range.trim();
  const minimum = trimmed.startsWith('>=') ? trimmed.slice(2) : trimmed;
  return compareSemver(parseSemver(version), parseSemver(minimum)) >= 0;
}
