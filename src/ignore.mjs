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
/** File extensions that are data or docs, not source code (never "monolithic code", rarely client code). */
export const NON_CODE_EXTS = new Set(['json', 'jsonl', 'md', 'csv', 'txt', 'lock']);

/**
 * Does a repo-relative path end in a non-code extension (JSON data, docs, …)?
 * @param {string} repoFile — repo-relative path.
 * @returns {boolean}
 */
export function hasNonCodeExt(repoFile) {
  const ext = repoFile.split('.').pop()?.toLowerCase() ?? '';
  return NON_CODE_EXTS.has(ext);
}

/**
 * Is this a test or fixture file? Hard-coded "secrets" in tests are almost
 * always fake fixtures (e.g. a 32-char hex token), so TD-016 skips them rather
 * than cry wolf. A real key committed to a test file is still committed code,
 * but that is rarer and outside TD-016's "shipped to the browser" premise.
 * @param {string} repoFile — repo-relative path.
 * @returns {boolean}
 */
export function isTestFile(repoFile) {
  const segments = repoFile.split(/[\\/]/);
  const base = segments.pop() ?? '';
  // `inbound.test.js`, `foo.spec.ts`, `test_foo.py`, `foo_test.py`, `foo.test`…
  if (/\.(test|spec)(\.|$)|^test_|_test\./i.test(base)) return true;
  // …or anywhere under a test / fixture directory.
  return segments.some((segment) => /^(tests?|__tests__|fixtures?|spec|mocks?)$/i.test(segment));
}