// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Wildcard-CORS provider — LastMile "Hardener" framework.
 *
 * Complements the live probe: `vibe-check probe` sees the CORS headers the
 * DEPLOYED app serves; this provider sees the CORS configuration in CODE and
 * committed hosting config. It flags wildcard CORS —
 *
 *   - JS/TS: `cors({ origin: '*' })`, `Access-Control-Allow-Origin: *`
 *   - Python: `allow_origins=["*"]`, `CORSMiddleware`
 *   - PHP: `header('Access-Control-Allow-Origin: *')`
 *   - hosting config: nginx `add_header Access-Control-Allow-Origin *`,
 *     `.htaccess`, `Caddyfile`, Netlify `_headers`
 *
 * Wildcard CORS is a deliberate choice for public APIs — so this is an
 * **advisory** (reported, not scored). Two nuances make it worth reporting:
 *   - wildcard + credentials (`credentials: true` / `allow_credentials=True` /
 *     `Access-Control-Allow-Credentials: true`) is a BROKEN combination —
 *     browsers reject the response — and signals the intent to accept
 *     credentials from any origin;
 *   - wildcard CORS on an app that uses cookie auth is the same exposure as
 *     missing CSRF protection (see the `csrf` provider).
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { IGNORED_DIRS } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */

/** npm dependency names that imply a web server owns CORS. */
const NPM_SERVER_DEPS = new Set(['express', 'next', 'koa', 'fastify', '@nestjs/core', 'hono', 'sveltekit']);

/** Python package names that imply a web server owns CORS. */
const PY_SERVER_DEPS = new Set(['flask', 'fastapi', 'django', 'starlette', 'aiohttp', 'sanic', 'tornado']);

/** Source file extensions whose text is scanned for CORS evidence. */
const CODE_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php']);

/** Hosting config basenames that set CORS outside application code. */
const HOSTING_CONFIGS = new Set(['nginx.conf', '.htaccess', 'Caddyfile', '_headers', 'netlify.toml']);

/**
 * Wildcard-CORS evidence. `origin: '*'` / `allow_origins=["*"]` /
 * `Access-Control-Allow-Origin: *` (header strings, nginx `add_header`,
 * `.htaccess` `Header set`, Caddyfile `header`).
 */
const WILDCARD_CORS_RE =
  /origin\s*:\s*["']\*["']|allow_origins\s*=\s*\[?["']\*["']\]?|Access-Control-Allow-Origin["']?\s*:\s*["']?\s*\*|add_header\s+Access-Control-Allow-Origin\s+(?:always\s+)?["']?\*["']?|Header\s+(?:always\s+)?set\s+Access-Control-Allow-Origin\s+["']?\*["']?|header\s+Access-Control-Allow-Origin\s+\*/i;

/** Credentials-alongside-wildcard signal (broken + intent-revealing). */
const CREDENTIALS_RE =
  /credentials\s*:\s*true|Access-Control-Allow-Credentials\s*:\s*true|allow_credentials\s*=\s*True/i;

/** @type {Provider} */
export const corsProvider = {
  id: 'cors',
  name: 'Wildcard CORS',
  available: () => Promise.resolve(true),
  applicable: () => true,
  async run(_config, ctx) {
    const files = collectAll(ctx.repoRoot, ctx.targets);
    if (files.length === 0) {
      ctx.log('  no existing targets — nothing to scan');
      return [];
    }

    const frameworks = detectServerFrameworks(ctx.repoRoot, files);
    if (frameworks.size === 0) {
      ctx.log('  no server framework or hosting config — skipping');
      return [];
    }
    ctx.log(`  server(s): ${[...frameworks].join(', ')}`);

    /** @type {Finding[]} */
    const findings = [];
    for (const file of files) {
      if (!isScannable(file)) continue;
      let content = '';
      try {
        content = readFileSync(join(ctx.repoRoot, file), 'utf8');
      } catch {
        continue;
      }
      // Bound the scan per file — CORS setup lives near the top.
      if (!WILDCARD_CORS_RE.test(content.slice(0, 200000))) continue;
      findings.push(wildcardFinding(file, CREDENTIALS_RE.test(content.slice(0, 200000))));
    }
    return findings;
  },
};

/**
 * Should this file be scanned for CORS evidence? Code files only for
 * server-framework repos (an SPA-only repo has no CORS to configure);
 * hosting configs always (their presence implies hosting).
 * @param {string} file — repo-relative path.
 * @returns {boolean}
 */
function isScannable(file) {
  const base = file.split(/[\\/]/).pop() ?? '';
  if (HOSTING_CONFIGS.has(base)) return true;
  const dot = file.lastIndexOf('.');
  if (dot === -1) return false;
  return CODE_EXTS.has(file.slice(dot).toLowerCase()) || base.endsWith('.conf');
}

/**
 * The wildcard-CORS advisory for one file.
 * @param {string} file
 * @param {boolean} withCredentials
 * @returns {Finding}
 */
function wildcardFinding(file, withCredentials) {
  const credentialsNote = withCredentials
    ? ' Credentials are also enabled alongside the wildcard — browsers reject that combination, and it signals the intent to accept credentials from any origin.'
    : '';
  return {
    id: `cors:wildcard:${file}`,
    kind: 'hygiene',
    file,
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'security',
    teardownId: null,
    title: 'Wildcard CORS in server configuration',
    message: `${file} allows every origin (Access-Control-Allow-Origin: *). A public API may do this deliberately — if not, restrict it to your frontend's origin(s).${credentialsNote}`,
    fixSummary:
      'Restrict CORS to the exact origins that need it: Express → cors({ origin: [...allowlist] }); FastAPI → CORSMiddleware(allow_origins=[...]); PHP → header only for allowlisted origins. Wildcard + credentials is never valid — browsers reject it.',
    source: { provider: 'cors', ruleId: 'wildcard-cors' },
    dependency: null,
    // Advisory: wildcard CORS is a deliberate, common choice for public APIs.
    advisory: true,
  };
}

/**
 * Detect web-server frameworks from package manifests.
 * @param {string} repoRoot
 * @param {string[]} files — repo-relative paths collected under targets + root.
 * @returns {Set<string>} detected framework/package names.
 */
function detectServerFrameworks(repoRoot, files) {
  /** @type {Set<string>} */
  const frameworks = new Set();

  for (const file of files) {
    const base = file.split(/[\\/]/).pop() ?? '';
    if (HOSTING_CONFIGS.has(base)) {
      frameworks.add(base);
      continue;
    }
    if (base === 'package.json') {
      let data;
      try {
        data = JSON.parse(readFileSync(join(repoRoot, file), 'utf8'));
      } catch {
        continue;
      }
      for (const key of ['dependencies', 'devDependencies', 'peerDependencies']) {
        const deps = /** @type {Record<string, unknown> | undefined} */ (data?.[key]);
        if (!deps || typeof deps !== 'object') continue;
        for (const name of Object.keys(deps)) {
          if (NPM_SERVER_DEPS.has(name)) frameworks.add(name);
        }
      }
    } else if (base === 'requirements.txt') {
      let content = '';
      try {
        content = readFileSync(join(repoRoot, file), 'utf8');
      } catch {
        continue;
      }
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
        const pkg = trimmed.split(/[<>=~!*[\s#]/)[0].trim().toLowerCase();
        if (PY_SERVER_DEPS.has(pkg)) frameworks.add(pkg);
      }
    } else if (base === 'composer.json') {
      frameworks.add('php'); // any composer app with a web entry can set CORS headers
    } else if (base.endsWith('.php')) {
      frameworks.add('php');
    }
  }
  return frameworks;
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
  for (const base of ['package.json', 'requirements.txt', 'pyproject.toml', 'composer.json', 'nginx.conf', '.htaccess', 'Caddyfile', '_headers', 'netlify.toml']) {
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
