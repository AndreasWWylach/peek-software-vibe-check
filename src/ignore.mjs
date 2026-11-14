// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Shared path filters — junk directories and env files that no
 * provider should scan (dependency trees, build output, caches, and the local
 * `.env` secret store). A single source of truth so every provider agrees on
 * what counts as "the app's own source".
 */

/** Directory names that are never part of the app's own source. */
export const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.cache',
  'dist',
  'build',
  '.next',
  'coverage',
  '.venv',
  'venv',
  '__pycache__',
  '.idea',
  '.vscode',
  '.turbo',
  'vendor',
]);

/**
 * Does a repo-relative path sit under (or equal) an ignored directory?
 * @param {string} repoFile — repo-relative path, `/` or `\\` separators.
 * @returns {boolean}
 */
export function isIgnoredDir(repoFile) {
  return repoFile.split(/[\\/]/).some((segment) => IGNORED_DIRS.has(segment));
}

/**
 * Is this a local environment file (`.env`, `.env.local`, …)? These hold the
 * developer's own secrets and are almost always gitignored — flagging them as
 * "secret shipped to the browser" (TD-016) is misleading.
 * @param {string} repoFile — repo-relative path.
 * @returns {boolean}
 */
export function isEnvFile(repoFile) {
  const base = repoFile.split(/[\\/]/).pop() ?? '';
  return base === '.env' || base.startsWith('.env.');
}
