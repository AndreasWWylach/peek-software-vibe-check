// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview CSRF protection provider — LastMile "Hardener" framework.
 *
 * Cross-site request forgery only applies to apps authenticated by COOKIES —
 * bearer-token apps (JWT in Authorization headers) are immune by default. So
 * the check has two gates:
 *
 *   1. Cookie-based auth must be DETECTED (session libraries, next-auth,
 *      Supabase SSR, PHP `session_start`). Token-only apps stay silent.
 *   2. CSRF protection evidence must be ABSENT — token middleware/libraries
 *      (csurf, lusca, Flask-WTF, Symfony/Laravel built-ins), token handling in
 *      code (`csrfToken`, `X-CSRF-Token`, …), or a `SameSite=Lax|Strict`
 *      cookie attribute, which neutralizes classic CSRF.
 *
 * Absence of evidence is a signal, not a proof — protection may live at a
 * gateway, or every state-changing route may be token-checked elsewhere. So
 * the finding is an **advisory** (reported, not scored), worded accordingly.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { IGNORED_DIRS } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */

/** npm deps that imply cookie/session-based authentication. */
const NPM_COOKIE_AUTH = new Set([
  'express-session',
  'cookie-session',
  'iron-session',
  '@fastify/session',
  'fastify-session',
  'next-auth',
  '@supabase/ssr',
  '@supabase/auth-helpers-nextjs',
]);

/** npm deps that implement CSRF protection (token middleware/generators). */
const NPM_CSRF_DEPS = new Set([
  'csurf',
  'lusca',
  'csrf',
  'tiny-csrf',
  'next-csrf',
  'edge-csrf',
  '@edge-csrf/nextjs',
  '@fastify/csrf-protection',
  'fastify-csrf-protect',
]);

/** Python packages: cookie/session auth (django is its own case — see below). */
const PY_COOKIE_AUTH = new Set(['flask', 'flask-login']);

/** Python packages: CSRF protection. */
const PY_CSRF_DEPS = new Set(['flask-wtf', 'django']);

/** composer packages: CSRF protection is built in (forms/session tokens). */
const COMPOSER_CSRF_BUILTIN = new Set([
  'symfony/security-csrf',
  'laravel/framework',
  // Framework bundles ship the CSRF token infrastructure by default
  // (Symfony forms generate tokens unless explicitly disabled).
  'symfony/framework-bundle',
  'pimcore/pimcore',
]);

/** Source file extensions whose text is scanned for CSRF evidence. */
const CODE_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php']);

/**
 * Evidence of CSRF protection or SameSite mitigation in application code.
 * `sameSite`/`SameSite` anywhere is accepted: Strict/Lax neutralize classic
 * CSRF, and `none` is only valid WITH the attribute being set explicitly
 * (cookie libs default to Lax when the option is absent).
 */
const CSRF_EVIDENCE_RE =
  /\bcsrfToken\b|\b_csrf\b|X-CSRF-Token|CSRFProtect|flask_wtf|\bcsrf_protect\b|generate_csrf|\bcsrf_token\b|verifyCsrf|checkCsrf|SameSite|sameSite/;

/** PHP cookie sessions start here — a strong cookie-auth signal. */
const PHP_SESSION_RE = /\bsession_start\s*\(/;

/** @type {Provider} */
export const csrfProvider = {
  id: 'csrf',
  name: 'CSRF protection',
  available: () => Promise.resolve(true),
  applicable: () => true,
  async run(_config, ctx) {
    const files = collectAll(ctx.repoRoot, ctx.targets);
    if (files.length === 0) {
      ctx.log('  no existing targets — nothing to scan');
      return [];
    }

    const auth = detectCookieAuth(ctx.repoRoot, files);
    if (auth.kind === 'none') {
      ctx.log('  no cookie-based auth detected — CSRF not applicable');
      return [];
    }
    if (auth.kind === 'builtin-protected') {
      ctx.log(`  CSRF built in (${auth.label}) — nothing to flag`);
      return [];
    }

    const protectedEvidence = findCsrfEvidence(ctx.repoRoot, files);
    ctx.log(`  cookie auth: ${auth.label}; CSRF evidence: ${protectedEvidence ? 'yes' : 'no'}`);

    if (protectedEvidence) return [];
    return [noCsrfFinding(auth, ctx)];
  },
};

/**
 * Detect cookie-based authentication from manifests + PHP session usage.
 * `django` counts as protected by default (its CSRF middleware is on unless
 * explicitly disabled), so it is folded into the `protected` bucket by the
 * caller — here it is reported as `builtin-protected`.
 *
 * @param {string} repoRoot
 * @param {string[]} files — repo-relative paths.
 * @returns {{ kind: 'none' } | { kind: 'cookie-auth'; label: string } | { kind: 'builtin-protected'; label: string }}
 */
export function detectCookieAuth(repoRoot, files) {
  /** @type {Set<string>} */
  const cookieAuth = new Set();
  /** @type {Set<string>} */
  const builtin = new Set();
  /** @type {boolean} */
  let phpSession = false;

  for (const file of files) {
    const base = file.split(/[\\/]/).pop() ?? '';
    if (base === 'package.json') {
      const deps = readJsonDeps(join(repoRoot, file));
      for (const name of Object.keys(deps)) {
        if (NPM_COOKIE_AUTH.has(name)) cookieAuth.add(name);
        if (NPM_CSRF_DEPS.has(name)) builtin.add(name);
      }
    } else if (base === 'requirements.txt') {
      for (const pkg of readRequirements(join(repoRoot, file))) {
        if (PY_COOKIE_AUTH.has(pkg)) cookieAuth.add(pkg);
        if (PY_CSRF_DEPS.has(pkg)) builtin.add(pkg);
      }
    } else if (base === 'composer.json') {
      const deps = readJsonDeps(join(repoRoot, file));
      for (const name of Object.keys(deps)) {
        if (COMPOSER_CSRF_BUILTIN.has(name)) builtin.add(name);
      }
    } else if (base === 'composer.lock') {
      // Transitive packages live only in the lockfile — Pimcore's
      // symfony/security-csrf is a classic case.
      for (const name of readComposerLockNames(join(repoRoot, file))) {
        if (COMPOSER_CSRF_BUILTIN.has(name)) builtin.add(name);
      }
    } else if (base.endsWith('.php') && !phpSession) {
      let content = '';
      try {
        content = readFileSync(join(repoRoot, file), 'utf8');
      } catch {
        continue;
      }
      // Bound the scan: only the session bootstrap matters.
      if (PHP_SESSION_RE.test(content.slice(0, 40000))) phpSession = true;
    }
  }

  if (builtin.size > 0) {
    return { kind: 'builtin-protected', label: [...builtin].join(', ') };
  }
  if (phpSession) {
    return { kind: 'cookie-auth', label: 'PHP session_start' };
  }
  if (cookieAuth.size > 0) {
    return { kind: 'cookie-auth', label: [...cookieAuth].join(', ') };
  }
  return { kind: 'none' };
}

/**
 * Does any source file contain CSRF-protection evidence?
 * @param {string} repoRoot
 * @param {string[]} files
 * @returns {boolean}
 */
export function findCsrfEvidence(repoRoot, files) {
  for (const file of files) {
    const dot = file.lastIndexOf('.');
    if (dot === -1 || !CODE_EXTS.has(file.slice(dot).toLowerCase())) continue;
    let content = '';
    try {
      content = readFileSync(join(repoRoot, file), 'utf8');
    } catch {
      continue;
    }
    // Bound the scan per file — evidence shows up in middleware/session setup.
    if (CSRF_EVIDENCE_RE.test(content.slice(0, 200000))) return true;
  }
  return false;
}

/**
 * The "no CSRF protection" advisory.
 * @param {{ kind: 'cookie-auth'; label: string }} auth
 * @param {RunContext} ctx
 * @returns {Finding}
 */
function noCsrfFinding(auth, ctx) {
  const anchor = ctx.targets[0] ? toRepoFile(ctx.targets[0], ctx.repoRoot) : '.';
  return {
    id: 'csrf:no-csrf-protection',
    kind: 'hygiene',
    file: anchor,
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'security',
    teardownId: null,
    title: 'Cookie-based authentication without detected CSRF protection',
    message: `Cookie/session authentication was detected (${auth.label}), but no CSRF protection was found — no token middleware (csurf, lusca, Flask-WTF, Symfony/Laravel built-ins), no token handling in code (csrfToken, X-CSRF-Token, …), and no SameSite=Lax|Strict cookie attribute. Any state-changing endpoint that trusts the session cookie can be triggered cross-site. Protection may live at a gateway or in code the scanner cannot see — if so, this is a false positive.`,
    fixSummary: 'Add CSRF protection: Express → csurf/lusca middleware or sameSite on the session cookie; Next.js → a csrf token per mutating request or sameSite strict (next-auth protects only its own endpoints); Flask → Flask-WTF CSRFProtect; PHP → per-form tokens (Symfony forms/Laravel do this by default).',
    source: { provider: 'csrf', ruleId: 'no-csrf-protection' },
    dependency: null,
    // Advisory: absence-of-evidence is a signal, not a proven defect.
    advisory: true,
  };
}

/**
 * Package names declared in a composer.lock (`packages` + `packages-dev`).
 * @param {string} file
 * @returns {Set<string>}
 */
function readComposerLockNames(file) {
  /** @type {Set<string>} */
  const names = new Set();
  let data;
  try {
    data = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return names;
  }
  for (const key of ['packages', 'packages-dev']) {
    const list = /** @type {Array<Record<string, unknown>> | undefined} */ (data?.[key]);
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (typeof item?.name === 'string') names.add(item.name);
    }
  }
  return names;
}

/**
 * The dependency maps of a JSON manifest (all dep sections merged).
 * @param {string} file
 * @returns {Record<string, unknown>}
 */
function readJsonDeps(file) {
  let data;
  try {
    data = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
  /** @type {Record<string, unknown>} */
  const merged = {};
  for (const key of ['dependencies', 'devDependencies', 'peerDependencies', 'require', 'require-dev']) {
    const deps = /** @type {Record<string, unknown> | undefined} */ (data?.[key]);
    if (deps && typeof deps === 'object') Object.assign(merged, deps);
  }
  return merged;
}

/**
 * Package names declared in a requirements.txt.
 * @param {string} file
 * @returns {Set<string>}
 */
function readRequirements(file) {
  /** @type {Set<string>} */
  const packages = new Set();
  let content = '';
  try {
    content = readFileSync(file, 'utf8');
  } catch {
    return packages;
  }
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
    packages.add(trimmed.split(/[<>=~!*[\s#]/)[0].trim().toLowerCase());
  }
  return packages;
}

/**
 * Recursively collect repo-relative file paths under targets + root manifests.
 * @param {string} repoRoot
 * @param {string[]} targets — absolute target paths.
 * @returns {string[]} repo-relative paths (deduplicated).
 */
function collectAll(repoRoot, targets) {
  /** @type {string[]} */
  const out = [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const target of targets) walk(target, repoRoot, out, seen);
  for (const base of ['package.json', 'requirements.txt', 'pyproject.toml', 'composer.json', 'composer.lock']) {
    if (existsSync(join(repoRoot, base)) && !seen.has(base)) out.push(base);
  }
  return out;
}

/**
 * Walk a directory (or single file target), collecting repo-relative paths.
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
    if (!seen.has(repoFile)) {
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
      if (IGNORED_DIRS.has(entry.name)) continue;
      walk(abs, repoRoot, out, seen);
    } else {
      const repoFile = toRepoFile(abs, repoRoot);
      if (!seen.has(repoFile)) {
        seen.add(repoFile);
        out.push(repoFile);
      }
    }
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
