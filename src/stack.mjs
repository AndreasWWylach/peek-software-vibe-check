// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Scan-time stack detection.
 *
 * Framework/service markers are read from the repo itself — `firebase.json`,
 * `package.json` dependencies, `*.rules` files, `schema.prisma` — never asked
 * of the user (the same "the code knows, so read the code" principle as the
 * tenant-column auto-detection). Markers both gate framework-specific rules
 * and feed the report's App Stack summary.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { IGNORED_DIRS } from './ignore.mjs';

/** package.json dependency name → stack marker. */
const DEP_MARKERS = /** @type {Record<string, string>} */ (
  Object.freeze({
    'firebase-functions': 'cloudFunctions',
    'firebase-admin': 'firebaseAdmin',
    firebase: 'firebase',
    '@google-cloud/firestore': 'firestore',
    '@google-cloud/storage': 'storage',
    prisma: 'prisma',
    '@prisma/client': 'prisma',
    express: 'express',
    next: 'next',
    react: 'react',
    vue: 'vue',
    vite: 'vite',
    stripe: 'stripe',
    '@stripe/stripe-js': 'stripe',
  })
);

/**
 * Detect the app's stack markers (see DEP_MARKERS) + locate the security-rules
 * files. Deterministic and offline — reads file names and package manifests.
 * @param {string} repoRoot
 * @param {string[]} targets — absolute target paths.
 * @returns {{ markers: Set<string>; rulesFiles: Map<string, string> }}
 */
export function scanRepo(repoRoot, targets) {
  /** @type {Set<string>} */
  const markers = new Set();
  /** @type {Map<string, string>} basename → repo-relative path (first found). */
  const rulesFiles = new Map();

  if (existsSync(join(repoRoot, 'firebase.json'))) markers.add('firebase');
  readPackageJson(join(repoRoot, 'package.json'), markers);

  for (const target of targets) {
    walk(target, repoRoot, markers, rulesFiles);
  }
  return { markers, rulesFiles };
}

/**
 * Stack markers as a plain `{ marker: true }` object (for the report + schema).
 * @param {string} repoRoot
 * @param {string[]} targets
 * @returns {Record<string, boolean>}
 */
export function detectStack(repoRoot, targets) {
  const { markers } = scanRepo(repoRoot, targets);
  /** @type {Record<string, boolean>} */
  const out = {};
  for (const marker of [...markers].sort()) out[marker] = true;
  return out;
}

/**
 * Locate a security-rules file (e.g. `firestore.rules`) repo-relative, or null.
 * @param {string} repoRoot
 * @param {string[]} targets
 * @param {string} name — file basename to find.
 * @returns {string | null}
 */
export function findRulesFile(repoRoot, targets, name) {
  const { rulesFiles } = scanRepo(repoRoot, targets);
  return rulesFiles.get(name) ?? null;
}

/**
 * Recursively walk a directory, recording stack markers + rules-file paths.
 * @param {string} dir
 * @param {string} repoRoot
 * @param {Set<string>} markers
 * @param {Map<string, string>} rulesFiles
 */
function walk(dir, repoRoot, markers, rulesFiles) {
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
      if (IGNORED_DIRS.has(entry.name)) continue;
      walk(abs, repoRoot, markers, rulesFiles);
    } else if (entry.isFile()) {
      if (entry.name === 'package.json') {
        readPackageJson(abs, markers);
      } else if (entry.name === 'firestore.rules') {
        markers.add('firestore');
        recordFile(rulesFiles, entry.name, abs, repoRoot);
      } else if (entry.name === 'storage.rules') {
        markers.add('storage');
        recordFile(rulesFiles, entry.name, abs, repoRoot);
      } else if (entry.name === 'schema.prisma') {
        markers.add('prisma');
      } else if (entry.name === 'firebase.json') {
        markers.add('firebase');
      }
    }
  }
}

/**
 * Read a package.json and add markers for its dependencies.
 * @param {string} file
 * @param {Set<string>} markers
 */
function readPackageJson(file, markers) {
  let text = '';
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    return;
  }
  /** @type {Record<string, unknown>} */
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch {
    return;
  }
  const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  for (const name of Object.keys(deps)) {
    const marker = DEP_MARKERS[name];
    if (marker) markers.add(marker);
    // The Admin SDK is the server-side path to Firestore — strong enough signal.
    if (name === 'firebase-admin') markers.add('firestore');
  }
}

/**
 * Record the first repo-relative path for a rules-file basename.
 * @param {Map<string, string>} rulesFiles
 * @param {string} name
 * @param {string} abs
 * @param {string} repoRoot
 */
function recordFile(rulesFiles, name, abs, repoRoot) {
  if (rulesFiles.has(name)) return;
  const repoFile = isAbsolute(abs) ? relative(repoRoot, abs).replace(/^[/\\]+/, '') : abs;
  rulesFiles.set(name, repoFile);
}
