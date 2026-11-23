// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Rate-limiting provider — LastMile "Hardener" framework.
 *
 * Detects a web-server framework (Express/Next/Koa/Fastify/NestJS/Hono, or
 * Flask/FastAPI/Django/Starlette), then checks for evidence that request
 * rate limiting exists anywhere in the repo: a rate-limiting dependency, a
 * recognizable usage pattern, or committed reverse-proxy config
 * (`limit_req`).
 *
 * Rate limiting commonly lives at a managed gateway OUTSIDE the repo
 * (Cloudflare, AWS WAF, API Gateway) — invisible to a local scanner. So the
 * finding is an **advisory** (reported, not scored), worded accordingly.
 * Absence of evidence is a signal, not a proof.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { isIgnoredDir } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */

/** npm dependency names that imply a web server owns the rate-limit decision. */
const NPM_SERVER_DEPS = new Set(['express', 'next', 'koa', 'fastify', '@nestjs/core', 'hono', 'sveltekit']);

/** Python package names that imply a web server owns the rate-limit decision. */
const PY_SERVER_DEPS = new Set(['flask', 'fastapi', 'django', 'starlette', 'aiohttp', 'sanic', 'tornado']);

/** npm rate-limiting packages. */
const NPM_RATELIMIT_DEPS = new Set([
  'express-rate-limit',
  'rate-limiter-flexible',
  'express-slow-down',
  '@nestjs/throttler',
  '@fastify/rate-limit',
  'fastify-rate-limit',
  'koa-ratelimit',
  '@upstash/ratelimit',
  '@upstash/redis', // the store behind upstash/ratelimit - only counts WITH @upstash/ratelimit
]);

/** Python rate-limiting packages. */
const PY_RATELIMIT_DEPS = new Set(['flask-limiter', 'flask_limiter', 'slowapi', 'django-ratelimit', 'django-axes']);

/** Source file extensions whose text is scanned for rate-limit evidence. */
const CODE_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php']);

/** Reverse-proxy config file extensions whose text is scanned for `limit_req`. */
const CONF_EXTS = new Set(['.conf', '.nginx', '.cfg']);

/** Evidence that rate limiting is wired in application code. */
const RATELIMIT_EVIDENCE_RE =
  /\brateLimit\b|\brate_limit\b|Limiter\s*\(|@limiter\b|@ratelimit\b|@Throttle\s*\(|throttle:\s*['"]|ThrottleRequests|DEFAULT_THROTTLE|ScopedRateThrottle|RATELIMIT_\w+|slidingWindow\s*\(|tokenBucket\s*\(|fixedWindow\s*\(/;

/** Evidence in committed reverse-proxy config. */
const NGINX_LIMIT_RE = /\blimit_req(_zone)?\b/;

/** @type {Provider} */
export const rateLimitProvider = {
  id: 'ratelimit',
  name: 'Rate limiting',
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

    const evidence = findRateLimitEvidence(ctx.repoRoot, files);
    ctx.log(`  server(s): ${[...frameworks].join(', ')}; rate-limit evidence: ${evidence ? 'yes' : 'no'}`);

    if (evidence) return [];
    return [noRateLimitingFinding(frameworks, ctx)];
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
 * Does the repo contain any rate-limiting evidence: a rate-limit dependency,
 * a usage pattern in code, or `limit_req` in committed reverse-proxy config?
 * @param {string} repoRoot
 * @param {string[]} files
 * @returns {boolean}
 */
function findRateLimitEvidence(repoRoot, files) {
  /** @type {Set<string>} */
  const npmDeps = new Set();
  /** @type {Set<string>} */
  const pyDeps = new Set();

  for (const file of files) {
    const base = file.split(/[\\/]/).pop() ?? '';
    const ext = file.slice(file.lastIndexOf('.')).toLowerCase();

    if (base === 'package.json') {
      collectNpmDeps(join(repoRoot, file), npmDeps);
      continue;
    }
    if (base === 'requirements.txt' || base === 'pyproject.toml') {
      collectPyDeps(join(repoRoot, file), pyDeps);
      continue;
    }

    let content = '';
    try {
      content = readFileSync(join(repoRoot, file), 'utf8');
    } catch {
      continue;
    }
    if (CODE_EXTS.has(ext) && RATELIMIT_EVIDENCE_RE.test(content)) return true;
    if (CONF_EXTS.has(ext) && NGINX_LIMIT_RE.test(content)) return true;
  }

  for (const dep of npmDeps) {
    if (NPM_RATELIMIT_DEPS.has(dep) && dep !== '@upstash/redis') return true;
    if (dep === '@upstash/redis' && npmDeps.has('@upstash/ratelimit')) return true;
  }
  for (const dep of pyDeps) {
    if (PY_RATELIMIT_DEPS.has(dep)) return true;
  }
  return false;
}

/**
 * @param {string} abs
 * @param {Set<string>} out
 */
function collectNpmDeps(abs, out) {
  let data;
  try {
    data = JSON.parse(readFileSync(abs, 'utf8'));
  } catch {
    return;
  }
  for (const key of ['dependencies', 'devDependencies', 'peerDependencies']) {
    const deps = /** @type {Record<string, unknown> | undefined} */ (data?.[key]);
    if (!deps || typeof deps !== 'object') continue;
    for (const name of Object.keys(deps)) out.add(name);
  }
}

/**
 * @param {string} abs
 * @param {Set<string>} out
 */
function collectPyDeps(abs, out) {
  let content = '';
  try {
    content = readFileSync(abs, 'utf8');
  } catch {
    return;
  }
  if (abs.endsWith('requirements.txt')) {
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
      out.add(trimmed.split(/[<>=~!*[\s#]/)[0].trim().toLowerCase());
    }
  } else {
    for (const dep of PY_RATELIMIT_DEPS) {
      if (new RegExp(`(^|\\s)${dep}\\s*(=|>|<)`, 'i').test(content)) out.add(dep);
    }
  }
}

/**
 * The "no rate limiting detected" advisory.
 * @param {Set<string>} frameworks
 * @param {RunContext} ctx
 * @returns {Finding}
 */
function noRateLimitingFinding(frameworks, ctx) {
  const anchor = ctx.targets[0] ? relative(ctx.repoRoot, ctx.targets[0]).replace(/^[/\\]+/, '') : '.';
  return {
    id: 'ratelimit:no-rate-limiting',
    kind: 'hygiene',
    file: anchor,
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'security',
    teardownId: null,
    title: 'No rate limiting detected',
    message: `A web server (${[...frameworks].join(', ')}) was detected, but no rate-limiting evidence (express-rate-limit, rate-limiter-flexible, flask-limiter, slowapi, django-ratelimit, an nginx limit_req, or a recognizable limiter pattern) was found in the repo. Rate limits may be enforced at a gateway outside the repo (Cloudflare, AWS WAF, API Gateway) — if so, this is a false positive.`,
    fixSummary: 'Add express-rate-limit / @nestjs/throttler (Node) or flask-limiter / slowapi / django-ratelimit (Python) on auth and expensive endpoints, or enforce limits at the reverse proxy (nginx limit_req).',
    source: { provider: 'ratelimit', ruleId: 'no-rate-limiting' },
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
    if (existsSync(join(repoRoot, base)) && !seen.has(base)) out.push(base);
  }
  // Root-level reverse-proxy configs carry the gateway-side evidence.
  /** @type {import('node:fs').Dirent[]} */
  let entries;
  try {
    entries = readdirSync(repoRoot, { withFileTypes: true });
  } catch {
    entries = [];
  }
  for (const entry of entries) {
    if (entry.isFile() && CONF_EXTS.has(entry.name.slice(entry.name.lastIndexOf('.')).toLowerCase()) && !seen.has(entry.name)) {
      out.push(entry.name);
    }
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
    const repoFile = relative(repoRoot, dir).replace(/^[/\\]+/, '');
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
    if (entry.isDirectory() && isIgnoredDir(entry.name)) continue;
    walk(join(dir, entry.name), repoRoot, out, seen);
  }
}
