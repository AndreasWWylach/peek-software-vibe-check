// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Security-headers provider — LastMile "Hardener" framework.
 *
 * Detects a web-server framework (Express/Next/Koa/Fastify/NestJS, or
 * Flask/FastAPI/Django/Starlette), then checks whether application code or
 * config sets response security headers (CSP / HSTS / X-Frame-Options /
 * X-Content-Type-Options / Referrer-Policy / Permissions-Policy).
 *
 * Absence of evidence is a *signal*, not a proof — headers may be set at a
 * reverse proxy the scanner can't see. So the finding is an **advisory**
 * (reported, not scored), worded accordingly.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { isIgnoredDir } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */

/** npm dependency names that imply a web server owns the response headers. */
const NPM_SERVER_DEPS = new Set(['express', 'next', 'koa', 'fastify', '@nestjs/core', 'hono', 'sveltekit']);

/** Python package names that imply a web server owns the response headers. */
const PY_SERVER_DEPS = new Set(['flask', 'fastapi', 'django', 'starlette', 'aiohttp', 'sanic', 'tornado']);

/** Source file extensions whose text is scanned for header evidence. */
const CODE_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

/** Evidence that security headers are configured in application code/config. */
const HEADER_EVIDENCE_RE =
  /Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy|\bhelmet\b|django-csp|Talisman|SECURE_HSTS_SECONDS|SECURE_SSL_REDIRECT|SECURE_CONTENT_TYPE_NOSNIFF|X_FRAME_OPTIONS/;

/** @type {Provider} */
export const headersProvider = {
  id: 'headers',
  name: 'Security headers',
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
      ctx.log('  no server framework detected — skipping');
      return [];
    }

    const evidence = findHeaderEvidence(ctx.repoRoot, files);
    ctx.log(`  server(s): ${[...frameworks].join(', ')}; header evidence: ${evidence ? 'yes' : 'no'}`);

    if (evidence) return [];
    return [noHeadersFinding(frameworks, ctx)];
  },
};

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
    } else if (base === 'pyproject.toml') {
      let content = '';
      try {
        content = readFileSync(join(repoRoot, file), 'utf8');
      } catch {
        continue;
      }
      for (const pkg of PY_SERVER_DEPS) {
        if (new RegExp(`(^|\\s)${pkg}\\s*(=|>|<)`, 'i').test(content)) frameworks.add(pkg);
      }
    }
  }
  return frameworks;
}

/**
 * Does any source file contain security-header configuration evidence?
 * @param {string} repoRoot
 * @param {string[]} files
 * @returns {boolean}
 */
function findHeaderEvidence(repoRoot, files) {
  for (const file of files) {
    const ext = file.slice(file.lastIndexOf('.')).toLowerCase();
    if (!CODE_EXTS.has(ext)) continue;
    let content = '';
    try {
      content = readFileSync(join(repoRoot, file), 'utf8');
    } catch {
      continue;
    }
    if (HEADER_EVIDENCE_RE.test(content)) return true;
  }
  return false;
}

/**
 * The "no security headers" advisory.
 * @param {Set<string>} frameworks
 * @param {RunContext} ctx
 * @returns {Finding}
 */
function noHeadersFinding(frameworks, ctx) {
  const anchor = ctx.targets[0] ? toRepoFile(ctx.targets[0], ctx.repoRoot) : '.';
  return {
    id: 'headers:no-security-headers',
    kind: 'hygiene',
    file: anchor,
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'security',
    teardownId: null,
    title: 'No security headers (CSP/HSTS/X-Frame-Options) detected',
    message: `A web server (${[...frameworks].join(', ')}) was detected, but no evidence of security headers (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options) was found in application code. Headers may be set at a reverse proxy — if so, this is a false positive.`,
    fixSummary: 'Set CSP, HSTS and X-Frame-Options via helmet() (Express), headers() in next.config.js, or Talisman/django-csp (Python).',
    source: { provider: 'headers', ruleId: 'no-security-headers' },
    dependency: null,
    // Advisory: absence-of-evidence is a signal, not a proven defect.
    advisory: true,
  };
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
  // Root manifests are outside targets but declare the server framework.
  for (const base of ['package.json', 'requirements.txt', 'pyproject.toml']) {
    if (existsSync(join(repoRoot, base))) out.push(base);
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
      if (isIgnoredDir(entry.name)) continue;
      walk(abs, repoRoot, out, seen);
    } else {
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
