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
import { basename, isAbsolute, join, relative } from 'node:path';
import { IGNORED_DIRS, isTestFile } from './ignore.mjs';

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
    // Postgres / Supabase markers gate the row-level-security check.
    '@supabase/supabase-js': 'supabase',
    '@supabase/ssr': 'supabase',
    pg: 'postgres',
    postgres: 'postgres',
  })
);

/** composer.json `require`/`require-dev` name → stack marker (PHP backends). */
const COMPOSER_MARKERS = /** @type {Record<string, string>} */ (
  Object.freeze({
    'pimcore/pimcore': 'pimcore',
    'laravel/framework': 'laravel',
    'doctrine/orm': 'doctrine',
    'doctrine/dbal': 'doctrine',
    'twig/twig': 'twig',
  })
);

/** Source file extensions whose content is scanned for Firebase signals. */
const SOURCE_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

/** Client SDK direct-Firestore usage (browser-side access gated by rules). */
const CLIENT_FIRESTORE_RE =
  /\bgetFirestore\s*\(\s*\)|firebase\.firestore\s*\(|initializeFirestore\s*\(/;

/** Client SDK Firebase Storage usage (bucket access gated by storage rules). */
const CLIENT_STORAGE_RE =
  /\bgetStorage\s*\(|firebase\.storage\s*\(|from\s+['"]firebase\/storage['"]/;

/** Cloud Function HTTP handlers (`onCall`/`onRequest`) — the callable surface. */
const FN_HANDLER_RE = /\bon(?:Call|Request)\s*\(/;

/** Auth tokens that a handler may use to verify the caller. */
const AUTH_RE =
  /\brequest\.auth\b|\bcontext\.auth\b|\bverifyIdToken\b|\bverifySessionCookie\b/;

/**
 * Detect the app's stack markers (see DEP_MARKERS) + locate the security-rules
 * files + Firebase content signals. Deterministic and offline — reads file
 * names, package manifests, and source-file text.
 * @param {string} repoRoot
 * @param {string[]} targets — absolute target paths.
 * @returns {{
 *   markers: Set<string>;
 *   rulesFiles: Map<string, string>;
 *   clientFirestore: boolean;
 *   unauthFunctions: string[];
 * }}
 */
export function scanRepo(repoRoot, targets) {
  /** @type {Set<string>} */
  const markers = new Set();
  /** @type {Map<string, string>} basename → repo-relative path (first found). */
  const rulesFiles = new Map();
  /** @type {{ clientFirestore: boolean; clientStorage: boolean; unauthFunctions: string[] }} */
  const state = { clientFirestore: false, clientStorage: false, unauthFunctions: [] };

  if (existsSync(join(repoRoot, 'firebase.json'))) markers.add('firebase');
  readPackageJson(join(repoRoot, 'package.json'), markers);
  readComposerJson(join(repoRoot, 'composer.json'), markers);
  // Rules files typically live at the repo root — outside any scan target.
  recordRootRules('firestore.rules', repoRoot, markers, rulesFiles);
  recordRootRules('storage.rules', repoRoot, markers, rulesFiles);
  recordRootStorageVariants(repoRoot, markers, rulesFiles);

  for (const target of targets) {
    walk(target, repoRoot, markers, rulesFiles, state);
  }
  // Client SDK direct usage implies the service, even without a rules file.
  if (state.clientFirestore) markers.add('firestore');
  if (state.clientStorage) markers.add('storage');
  return {
    markers,
    rulesFiles,
    clientFirestore: state.clientFirestore,
    unauthFunctions: state.unauthFunctions,
  };
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
 * Recursively walk a directory, recording stack markers, rules-file paths, and
 * Firebase content signals (client Firestore usage + unauthenticated handlers).
 * @param {string} dir
 * @param {string} repoRoot
 * @param {Set<string>} markers
 * @param {Map<string, string>} rulesFiles
 * @param {{ clientFirestore: boolean; clientStorage: boolean; unauthFunctions: string[] }} state
 */
function walk(dir, repoRoot, markers, rulesFiles, state) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const abs = join(dir, entry.name);
    // Test/fixture files (and whole test directories) never define the app's
    // stack — a fixture string that exercises the Firestore client SDK must
    // not make the engine think the repo ships a Firebase app.
    if (isTestFile(toRepoFile(abs, repoRoot))) continue;
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      walk(abs, repoRoot, markers, rulesFiles, state);
    } else if (entry.isFile()) {
      if (entry.name === 'package.json') {
        readPackageJson(abs, markers);
      } else if (entry.name === 'composer.json') {
        readComposerJson(abs, markers);
      } else if (entry.name === 'firestore.rules') {
        markers.add('firestore');
        recordFile(rulesFiles, entry.name, abs, repoRoot);
      } else if (/^storage\..*\.rules$/.test(entry.name)) {
        // `storage.rules`, `storage.rvmedia.rules`, ... - one file per bucket.
        markers.add('storage');
        recordFile(rulesFiles, entry.name, abs, repoRoot);
      } else if (entry.name === 'schema.prisma') {
        markers.add('prisma');
      } else if (entry.name === 'config.toml' && basename(dir) === 'supabase') {
        // `supabase/config.toml` — the canonical Supabase project marker, even
        // when the JS SDK is not a dependency.
        markers.add('supabase');
      } else if (entry.name === 'firebase.json') {
        markers.add('firebase');
      } else if (entry.name.toLowerCase().endsWith('.sql')) {
        markers.add('sql');
      } else if (isSourceFile(entry.name)) {
        scanSource(abs, repoRoot, state);
      }
    }
  }
}

/**
 * Whether a file name has a JS/TS source extension (content is scanned).
 * @param {string} name
 * @returns {boolean}
 */
function isSourceFile(name) {
  const dot = name.lastIndexOf('.');
  return dot !== -1 && SOURCE_EXTS.has(name.slice(dot).toLowerCase());
}

/**
 * Read a source file and record client-Firestore/storage usage + unauthenticated
 * Cloud Function handlers.
 * @param {string} abs
 * @param {string} repoRoot
 * @param {{ clientFirestore: boolean; clientStorage: boolean; unauthFunctions: string[] }} state
 */
function scanSource(abs, repoRoot, state) {
  let text = '';
  try {
    text = readFileSync(abs, 'utf8');
  } catch {
    return;
  }
  if (!state.clientFirestore && CLIENT_FIRESTORE_RE.test(text)) state.clientFirestore = true;
  if (!state.clientStorage && CLIENT_STORAGE_RE.test(text)) state.clientStorage = true;
  if (FN_HANDLER_RE.test(text) && !AUTH_RE.test(text)) {
    state.unauthFunctions.push(toRepoFile(abs, repoRoot));
  }
}

/**
 * Normalize an absolute path to a repo-relative one.
 * @param {string} abs
 * @param {string} repoRoot
 * @returns {string}
 */
function toRepoFile(abs, repoRoot) {
  if (isAbsolute(abs)) return relative(repoRoot, abs).replace(/^[/\\]+/, '');
  return abs.replace(/^[/\\]+/, '');
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
 * Read a composer.json and add markers for its `require`/`require-dev` packages
 * (Symfony/Pimcore/Doctrine/Twig/Laravel detection).
 * @param {string} file
 * @param {Set<string>} markers
 */
function readComposerJson(file, markers) {
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
  const deps = { ...(pkg.require ?? {}), ...(pkg['require-dev'] ?? {}) };
  for (const name of Object.keys(deps)) {
    if (name.startsWith('symfony/')) markers.add('symfony');
    if (name.startsWith('twig/')) markers.add('twig');
    const marker = COMPOSER_MARKERS[name];
    if (marker) markers.add(marker);
  }
}

/**
 * Record a rules file that sits directly at the repo root (outside targets).
 * @param {'firestore.rules' | 'storage.rules'} name
 * @param {string} repoRoot
 * @param {Set<string>} markers
 * @param {Map<string, string>} rulesFiles
 */
function recordRootRules(name, repoRoot, markers, rulesFiles) {
  const abs = join(repoRoot, name);
  if (!existsSync(abs)) return;
  markers.add(name === 'firestore.rules' ? 'firestore' : 'storage');
  recordFile(rulesFiles, name, abs, repoRoot);
}

/**
 * Record per-bucket storage rules variants at the repo root (`storage.*.rules`),
 * e.g. `storage.rvmedia.rules` in a shared Firebase project.
 * @param {string} repoRoot
 * @param {Set<string>} markers
 * @param {Map<string, string>} rulesFiles
 */
function recordRootStorageVariants(repoRoot, markers, rulesFiles) {
  let entries;
  try {
    entries = readdirSync(repoRoot, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isFile() && /^storage\..*\.rules$/.test(entry.name)) {
      markers.add('storage');
      recordFile(rulesFiles, entry.name, join(repoRoot, entry.name), repoRoot);
    }
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

/**
 * Recursively collect JS source text under a directory (skips ignored dirs).
 * @param {string} dir
 * @param {string[]} out — text chunks, appended in place.
 */
function collectJsText(dir, out) {
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
      collectJsText(abs, out);
    } else if (entry.isFile() && /\.(js|mjs|cjs)$/i.test(entry.name)) {
      try {
        out.push(readFileSync(abs, 'utf8'));
      } catch {
        // unreadable — skip
      }
    }
  }
}

/**
 * Whether Firebase App Check enforcement is OFF (callers are not verified).
 *
 * Readiness signal, not a rule: an app whose callables do not enforce App Check
 * accepts a forged client SDK, so it is a go-live condition. Returns null when
 * the app is not a Firebase Cloud Functions app.
 * @param {string} repoRoot
 * @param {Record<string, boolean> | undefined} stack
 * @returns {boolean | null} true = off, false = enforced, null = not applicable.
 */
export function detectAppCheckOff(repoRoot, stack) {
  if (!stack?.cloudFunctions && !stack?.firebaseAdmin) return null;
  /** @type {string[]} */
  const chunks = [];
  for (const dir of [join(repoRoot, 'functions'), join(repoRoot, 'src')]) {
    if (existsSync(dir)) collectJsText(dir, chunks);
  }
  const text = chunks.join('\n');
  // No App Check wiring at all → off. Literal `enforceAppCheck: true` → on.
  // The env-flag pattern (`enforceAppCheck: APP_CHECK_ENFORCE`, default off) →
  // off, which is the standard no-staging deployment seen in the wild.
  if (!/enforceAppCheck|APP_CHECK_ENFORCE/.test(text)) return true;
  return !/enforceAppCheck\s*:\s*true/.test(text);
}
