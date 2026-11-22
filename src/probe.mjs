// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Live deployment probe — the OPT-IN check of a deployed URL.
 *
 * `run` stays 100% offline. This command is the only network-touching feature
 * besides the OSV CVE lookup, and it talks exclusively to the URL the user
 * provides (their own deployment). Read-only GET/HEAD only, bounded request
 * count, redirect cap, per-request timeout — and loopback/private-network
 * targets are rejected outright. The probe never crawls, never submits, and
 * never sends credentials.
 *
 * Everything here is our own implementation — informed by what competing tools
 * describe in their READMEs, not their code (see docs/comparison.md).
 */
import { ENGINE_NAME, ENGINE_VERSION, readCommit } from './version.mjs';

/** Per-request timeout (ms). */
const TIMEOUT_MS = 5000;
/** Maximum redirects followed before giving up. */
const MAX_REDIRECTS = 5;
/** Maximum same-origin JS assets probed for public source maps. */
const MAX_SOURCE_MAP_PROBES = 10;
/** Maximum extra path probes (exposure + debug + source maps). */
const MAX_PATH_PROBES = 24;

/** Security headers expected on the final response of a production site. */
const EXPECTED_HEADERS = /** @type {const} */ ([
  ['content-security-policy', 'Content-Security-Policy'],
  ['strict-transport-security', 'Strict-Transport-Security'],
  ['x-frame-options', 'X-Frame-Options'],
  ['x-content-type-options', 'X-Content-Type-Options'],
  ['referrer-policy', 'Referrer-Policy'],
  ['permissions-policy', 'Permissions-Policy'],
]);

/** Well-known paths that must never be publicly reachable. */
const EXPOSURE_PATHS = ['/.env', '/.git/HEAD', '/.git/config'];

/** Common debug/API-docs endpoints that should not be live in production. */
const DEBUG_PATHS = ['/debug', '/swagger', '/swagger-ui', '/api/docs', '/actuator', '/docs'];

/** Hostname shapes that are never a valid probe target (accident guard). */
const PRIVATE_HOST_RE =
  /^(localhost|.*\.localhost|.*\.local)$|^127\.|^10\.|^192\.168\.|^169\.254\.|^172\.(1[6-9]|2\d|3[01])\.|^0\.|^\[?::1\]?$|^fe80:|^f[cd][0-9a-f]*:/i;

/** @typedef {'pass' | 'fail' | 'warn'} ProbeStatus */

/**
 * One probe result line.
 * @typedef {Object} ProbeResult
 * @property {string} id — stable check id.
 * @property {ProbeStatus} status
 * @property {string} title — one-line check name.
 * @property {string | null} detail — evidence / fix hint.
 */

/**
 * The complete probe report.
 * @typedef {Object} ProbeReport
 * @property {number} schemaVersion
 * @property {{ name: string; version: string; commit: string | null }} engine
 * @property {string} generatedAt
 * @property {string} target
 * @property {ProbeResult[]} results
 * @property {{ pass: number; fail: number; warn: number }} summary
 */

/**
 * Validate a probe target: http(s) URL only, and never loopback/private ranges.
 * @param {string} raw — the URL the user typed.
 * @returns {{ ok: true; url: URL } | { ok: false; reason: string }}
 */
export function validateProbeUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: `"${raw}" is not a valid URL.` };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { ok: false, reason: 'Only http:// and https:// targets are supported.' };
  }
  if (PRIVATE_HOST_RE.test(url.hostname)) {
    return { ok: false, reason: `"${url.hostname}" is a loopback/private address — the probe only targets public sites you own.` };
  }
  return { ok: true, url };
}

/**
 * One bounded GET/HEAD with redirect following (manual, capped) and a timeout.
 * @param {URL} url
 * @param {{ method?: 'GET' | 'HEAD' }} [options]
 * @returns {Promise<{ url: string; status: number; headers: Headers; body: string }>}
 */
async function fetchBounded(url, { method = 'GET' } = {}) {
  let current = new URL(url);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const response = await fetch(current, {
      method,
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { 'user-agent': `${ENGINE_NAME}/${ENGINE_VERSION}` },
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location) return { url: current.toString(), status: response.status, headers: response.headers, body: '' };
      current = new URL(location, current);
      continue;
    }
    const body = method === 'HEAD' ? '' : await response.text();
    return { url: current.toString(), status: response.status, headers: response.headers, body };
  }
  throw new Error(`too many redirects (more than ${MAX_REDIRECTS})`);
}

/** @param {string | null} value @returns {boolean} */
const has = (value) => typeof value === 'string' && value.length > 0;

/**
 * Is a 200 response with an HTML body an SPA fallback rather than a real file?
 * (SPA rewrites answer `index.html` for ANY path — a 200 on `/.env` is then a
 * false positive, so HTML responses to exposure paths are ignored.)
 * @param {{ status: number; headers: Headers; body: string }} response
 * @returns {boolean}
 */
export function looksLikeSpaFallback(response) {
  const type = response.headers.get('content-type') ?? '';
  return response.status === 200 && type.toLowerCase().includes('text/html');
}

/**
 * Probe a deployed URL. Read-only, bounded, deterministic per target state.
 * @param {string} raw — the target URL.
 * @param {{ log?: (line: string) => void }} [options]
 * @returns {Promise<ProbeReport>}
 */
export async function probeUrl(raw, options = {}) {
  const log = options.log ?? /** @param {string} _line */ ((_line) => {});
  const validated = validateProbeUrl(raw);

  /** @type {ProbeResult[]} */
  const results = [];
  /** @param {ProbeResult} result */
  const push = (result) => {
    results.push(result);
    log(`${result.status === 'pass' ? 'PASS' : result.status === 'fail' ? 'FAIL' : 'WARN'}  ${result.title}${result.detail ? ` — ${result.detail}` : ''}`);
  };

  if (!validated.ok) {
    push({ id: 'target-valid', status: 'fail', title: 'Valid public target', detail: validated.reason });
    return makeReport(raw, results);
  }

  const base = validated.url;
  log(`probing ${base.toString()}`);

  // ── Main request chain ────────────────────────────────────────────────
  /** @type {Awaited<ReturnType<typeof fetchBounded>> | null} */
  let main = null;
  try {
    main = await fetchBounded(base);
  } catch (err) {
    push({
      id: 'reachable',
      status: 'fail',
      title: 'Site reachable',
      detail: err instanceof Error ? err.message : String(err),
    });
    return makeReport(raw, results);
  }
  push({
    id: 'reachable',
    status: 'pass',
    title: 'Site reachable',
    detail: `GET ${base.toString()} → ${main.status}`,
  });

  const finalHttps = new URL(main.url).protocol === 'https:';
  push({
    id: 'https-final',
    status: finalHttps ? 'pass' : 'fail',
    title: 'Final transport is HTTPS',
    detail: finalHttps ? `final URL ${main.url}` : `served over ${new URL(main.url).protocol.replace(':', '')} at ${main.url}`,
  });

  // ── Live security headers ─────────────────────────────────────────────
  for (const [headerId, headerName] of EXPECTED_HEADERS) {
    const value = main.headers.get(headerId);
    push(
      has(value)
        ? { id: `header-${headerId}`, status: 'pass', title: `${headerName} header`, detail: null }
        : {
            id: `header-${headerId}`,
            status: 'warn',
            title: `${headerName} header`,
            detail: 'missing on the live response — often set by the host/CDN, not the repo.',
          },
    );
  }

  // ── CORS ──────────────────────────────────────────────────────────────
  const cors = main.headers.get('access-control-allow-origin');
  push({
    id: 'cors',
    status: cors === '*' ? 'fail' : 'pass',
    title: 'CORS not wide open',
    detail: cors === '*' ? 'Access-Control-Allow-Origin: * on the live response.' : null,
  });

  // ── Cookie flags ──────────────────────────────────────────────────────
  const setCookies = main.headers.getSetCookie ? main.headers.getSetCookie() : [];
  const missingCookieFlags = new Set();
  for (const cookie of setCookies) {
    if (!/;\s*secure\b/i.test(cookie)) missingCookieFlags.add('Secure');
    if (!/;\s*httponly\b/i.test(cookie)) missingCookieFlags.add('HttpOnly');
    if (!/;\s*samesite\s*=/i.test(cookie)) missingCookieFlags.add('SameSite');
  }
  push(
    setCookies.length === 0
      ? { id: 'cookies', status: 'pass', title: 'Cookie flags (no cookies set)', detail: null }
      : missingCookieFlags.size === 0
        ? { id: 'cookies', status: 'pass', title: 'Cookie flags', detail: `${setCookies.length} cookie(s), all hardened` }
        : {
            id: 'cookies',
            status: 'warn',
            title: 'Cookie flags',
            detail: `${setCookies.length} cookie(s) missing: ${[...missingCookieFlags].join(', ')}.`,
          },
  );

  // ── Server disclosure ─────────────────────────────────────────────────
  const powered = main.headers.get('x-powered-by');
  push(
    has(powered)
      ? { id: 'disclosure', status: 'warn', title: 'Server disclosure', detail: `X-Powered-By: ${powered} — reveals the stack.` }
      : { id: 'disclosure', status: 'pass', title: 'No X-Powered-By disclosure', detail: null },
  );

  // ── Bounded path probes ───────────────────────────────────────────────
  let probesUsed = 0;
  /** @param {URL} url @param {'GET' | 'HEAD'} [method] */
  const probe = async (url, method = 'GET') => {
    if (probesUsed >= MAX_PATH_PROBES) return null;
    probesUsed++;
    try {
      return await fetchBounded(url, { method });
    } catch {
      return null;
    }
  };

  // Exposed files.
  for (const path of EXPOSURE_PATHS) {
    const response = await probe(new URL(path, base));
    if (!response) continue;
    if (looksLikeSpaFallback(response)) continue;
    if (response.status === 200) {
      push({
        id: `exposed${path.replace(/[^a-z]/gi, '-')}`,
        status: 'fail',
        title: `${path} not publicly exposed`,
        detail: `GET ${path} → 200 — the file is served to the public.`,
      });
    }
  }

  // Public source maps — only same-origin JS assets referenced by the page.
  const assetUrls = extractSameOriginAssets(base, main.body);
  for (const asset of assetUrls.slice(0, MAX_SOURCE_MAP_PROBES)) {
    const mapUrl = new URL(`${asset.pathname}.map${asset.search}`, base);
    const response = await probe(mapUrl, 'HEAD');
    if (!response) continue;
    if (looksLikeSpaFallback(response)) continue;
    if (response.status === 200) {
      push({
        id: `sourcemap-${asset.pathname.split('/').pop() ?? 'asset'}`,
        status: 'fail',
        title: 'JavaScript source maps not public',
        detail: `HEAD ${mapUrl.pathname} → 200 — source maps expose the original source.`,
      });
    }
  }

  // Debug/docs endpoints.
  for (const path of DEBUG_PATHS) {
    const response = await probe(new URL(path, base));
    if (!response) continue;
    if (looksLikeSpaFallback(response)) continue;
    if (response.status === 200) {
      push({
        id: `debug-${path.replace(/[^a-z]/gi, '-')}`,
        status: 'warn',
        title: `${path} not exposed in production`,
        detail: `GET ${path} → 200 — debug/API documentation reachable.`,
      });
    }
  }

  if (probesUsed >= MAX_PATH_PROBES) {
    push({
      id: 'probe-cap',
      status: 'warn',
      title: 'Probe budget reached',
      detail: `capped at ${MAX_PATH_PROBES} extra requests — not every path was checked.`,
    });
  }

  return makeReport(raw, results);
}

/**
 * Same-origin JS asset URLs referenced by an HTML document (`<script src>`).
 * @param {URL} base
 * @param {string} html
 * @returns {URL[]}
 */
export function extractSameOriginAssets(base, html) {
  /** @type {URL[]} */
  const assets = [];
  const seen = new Set();
  const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
  let match;
  while ((match = re.exec(html))) {
    try {
      const url = new URL(match[1], base);
      if (url.origin !== base.origin) continue;
      if (!url.pathname.endsWith('.js')) continue;
      if (seen.has(url.href)) continue;
      seen.add(url.href);
      assets.push(url);
    } catch {
      // Ignore malformed src attributes.
    }
  }
  return assets;
}

/**
 * Assemble the report object.
 * @param {string} target
 * @param {ProbeResult[]} results
 * @returns {ProbeReport}
 */
function makeReport(target, results) {
  const summary = {
    pass: results.filter((result) => result.status === 'pass').length,
    fail: results.filter((result) => result.status === 'fail').length,
    warn: results.filter((result) => result.status === 'warn').length,
  };
  return {
    schemaVersion: 1,
    engine: { name: ENGINE_NAME, version: ENGINE_VERSION, commit: readCommit() },
    generatedAt: new Date().toISOString(),
    target,
    results,
    summary,
  };
}
