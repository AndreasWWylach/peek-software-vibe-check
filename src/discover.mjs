// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Source-directory discovery.
 *
 * The config's `targets` are a *hint* derived from the manifest intake — but
 * the upload may not cover every folder (e.g. a `shared/` the user didn't
 * include). The engine runs on the full repo, so it auto-includes any top-level
 * directory that contains source code of the configured languages. This keeps
 * the audit honest: no silently unchecked code.
 */
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { IGNORED_DIRS } from './ignore.mjs';

/** Language tag → source-file extensions. */
const LANG_EXTS = /** @type {Record<string, string[]>} */ (
  Object.freeze({
    javascript: ['.js', '.jsx', '.mjs', '.cjs'],
    typescript: ['.ts', '.tsx'],
    python: ['.py', '.pyi'],
    php: ['.php'],
    go: ['.go'],
    rust: ['.rs'],
    ruby: ['.rb'],
    java: ['.java', '.kt'],
  })
);

/**
 * Top-level directories under `repoRoot` that contain source code of the given
 * languages (recursively, skipping ignored dirs). Sorted, repo-relative with a
 * trailing slash (e.g. `["scripts/", "shared/"]`).
 * @param {string} repoRoot — absolute path to the repo.
 * @param {string[]} languages — config language tags.
 * @returns {string[]}
 */
export function discoverSourceDirs(repoRoot, languages) {
  const exts = new Set(
    languages.flatMap((language) => LANG_EXTS[language.toLowerCase()] ?? []),
  );
  if (exts.size === 0) return [];

  /** @type {string[]} */
  const dirs = [];
  let entries;
  try {
    entries = readdirSync(repoRoot, { withFileTypes: true });
  } catch {
    return [];
  }
  for (const entry of entries) {
    if (!entry.isDirectory() || IGNORED_DIRS.has(entry.name)) continue;
    if (containsSource(join(repoRoot, entry.name), exts)) dirs.push(`${entry.name}/`);
  }
  return dirs.sort();
}

/**
 * Does `dir` recursively contain at least one source file of the given exts?
 * @param {string} dir
 * @param {Set<string>} exts
 * @returns {boolean}
 */
function containsSource(dir, exts) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      if (containsSource(abs, exts)) return true;
    } else if (entry.isFile()) {
      const dot = entry.name.lastIndexOf('.');
      if (dot !== -1 && exts.has(entry.name.slice(dot).toLowerCase())) return true;
    }
  }
  return false;
}
