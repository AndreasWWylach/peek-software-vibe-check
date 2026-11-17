// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Gitleaks provider — hardcoded-secret detection (TD-016).
 *
 * Gitleaks scans files for high-entropy secrets (API keys, tokens, credentials)
 * with far higher precision than a regex — entropy + allowlists. It is the
 * preferred tool for TD-016 over Semgrep's prefix regex (docs §7.4). Offline,
 * deterministic; the secret VALUE is never copied into a finding (the report
 * must not re-expose the secret it just found).
 */
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { commandAvailable, runCommandCapture } from '../proc.mjs';
import { lookupTeardown } from '../catalog.mjs';
import { hasNonCodeExt, isEnvFile, isIgnoredDir, isSecretConfigFile, isVendoredPath } from '../ignore.mjs';
import { readLine, shouldSkipSecret } from '../secretClassify.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */
/** @typedef {import('../catalog.mjs').TeardownFact} TeardownFact */

/** The teardown this provider maps to (hardcoded API key / secret). */
const TEARDOWN_ID = 'TD-016';

/**
 * Whether a file is an unmistakable Firebase web SDK config, whose `apiKey` /
 * `appId` / site key are public by design (the real credential is the
 * project's security rules, not the key itself). Gitleaks flags these because
 * they look like API keys, but shipping them to the browser is correct.
 * @param {string} file — absolute path
 * @returns {boolean}
 */
function isFirebaseWebConfig(file) {
  try {
    const lower = readFileSync(file, 'utf8').toLowerCase();
    const has = (/** @type {string} */ needle) => lower.includes(needle.toLowerCase());
    // `authDomain` + `projectId` + an apiKey, inside a Firebase init/config
    // object, is the browser-SDK shape — never a server-side credential.
    // Case-insensitive so `DEFAULT_FIREBASE_CONFIG` / `FirebaseWebConfig` /
    // `firebaseConfig` spellings all match. The first three terms are already
    // Firebase-specific, so the 4th check needs only the `firebase` prefix.
    return has('authDomain') && has('projectId') && has('apiKey') && has('firebase');
  } catch {
    return false;
  }
}

/** Paths that clearly run server-side (never shipped to the browser). */
const SERVER_DIR_RE = /(^|\/)(server|backend|functions|api|config|environments|secrets|infra|deploy)\//;

/** Web-root prefixes whose contents ship to end users. */
const CLIENT_PATH_RE = /(^|\/)(public|frontend|client|www|static|assets|dist)\//;

/** Extensions that are client code (served to the browser). */
const CLIENT_EXTS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.html', '.htm', '.vue', '.svelte',
]);

/**
 * Is this repo-relative path client-exposed (shipped to the browser)? A secret
 * there is the TD-016 flaw — the key reaches end users.
 * @param {string} repoFile
 * @returns {boolean}
 */
function isClientExposed(repoFile) {
  const normalized = repoFile.replace(/\\/g, '/').toLowerCase();
  const dot = normalized.lastIndexOf('.');
  const ext = dot === -1 ? '' : normalized.slice(dot);
  if (SERVER_DIR_RE.test(normalized)) return false;
  return CLIENT_PATH_RE.test(normalized) || CLIENT_EXTS.has(ext);
}

/** Fallbacks when the vendored catalog does not yet carry TD-016. */
const DEFAULTS = {
  pillar: /** @type {Pillar} */ ('security'),
  severity: /** @type {Severity} */ ('critical'),
  fixSummary:
    'Move the secret to the server: use a server-only environment variable and call it from a route handler — never ship the SDK or the key to the browser.',
};

/** @type {Provider} */
export const gitleaksProvider = {
  id: 'gitleaks',
  name: 'Gitleaks (secrets)',
  available: () => commandAvailable('gitleaks'),
  // Gitleaks scans every file, not just one language — gate on `available`.
  applicable: () => true,
  async run(_config, ctx) {
    const targets = ctx.targets.filter((target) => existsSync(target));
    if (targets.length === 0) {
      ctx.log('  no existing targets — nothing to scan');
      return [];
    }

    const fact = await lookupTeardown(TEARDOWN_ID);
    /** @type {Finding[]} */
    const findings = [];
    let skipped = 0;
    let publicSkipped = 0;
    /** @type {Map<string, boolean>} Firebase web config memo, keyed by absolute path. */
    const firebaseMemo = new Map();
    for (const target of targets) {
      // `runCommandCapture` because gitleaks exits 1 when leaks are found (the
      // JSON report is still written to stdout via `--report-path -`).
      const { stdout } = runCommandCapture(
        'gitleaks',
        ['detect', '--no-git', '--source', target, '--report-format', 'json', '--report-path', '-'],
        { cwd: ctx.repoRoot },
      );
      for (const leak of parseGitleaksJson(stdout)) {
        // Relativize first: gitleaks echoes the absolute `--source` path, and
        // the ignore guards are segment-based on repo-relative paths.
        const repoFile = repoRelative(leak.file, ctx.repoRoot);
        // Skip junk dirs (node_modules, dist, …), vendored assets, the local
        // `.env` secret store, and data/docs files (JSON samples, Markdown) —
        // the latter two are not "hardcoded secret in client code".
        if (
          isIgnoredDir(repoFile) ||
          isVendoredPath(repoFile) ||
          isEnvFile(repoFile) ||
          hasNonCodeExt(repoFile)
        ) {
          skipped += 1;
          continue;
        }
        // Firebase web configs ship public keys by design — skip, not report.
        const abs = isAbsolute(leak.file) ? leak.file : join(ctx.repoRoot, leak.file);
        let firebase = firebaseMemo.get(abs);
        if (firebase === undefined) {
          firebase = isFirebaseWebConfig(abs);
          firebaseMemo.set(abs, firebase);
        }
        if (firebase) {
          publicSkipped += 1;
          continue;
        }
        // Value-level public-by-design: the Firebase Auth REST `key` (the public
        // web apiKey) and reCAPTCHA/App Check site keys. Inspects the flagged
        // line for a boolean decision only — never copies the value out.
        const flaggedLine = readLine(abs, leak.line);
        if (shouldSkipSecret(flaggedLine, abs)) {
          publicSkipped += 1;
          continue;
        }
        findings.push(toFinding(leak, ctx.repoRoot, fact));
      }
    }
    if (publicSkipped > 0) {
      ctx.log(`  gitleaks: skipped ${publicSkipped} public-by-design key(s) (Firebase web config / App Check site key / Firebase Auth REST key)`);
    }
    if (skipped > 0) {
      ctx.log(`  gitleaks: skipped ${skipped} leak(s) in ignored dirs / .env files`);
    }
    return findings;
  },
};

/**
 * Parse `gitleaks detect --report-format json` output — WITHOUT the secret.
 * @param {string} stdout
 * @returns {Array<{ ruleId: string; description: string; file: string; line: number }>}
 */
export function parseGitleaksJson(stdout) {
  const parsed = JSON.parse(stdout);
  const leaks = Array.isArray(parsed) ? parsed : [];
  return leaks.map((entry) => ({
    // Deliberately ignore `Secret` and `Match` — findings must never carry the
    // secret value (the report is written to disk and shared).
    ruleId: String(entry?.RuleID ?? ''),
    description: String(entry?.Description ?? ''),
    file: String(entry?.File ?? ''),
    line: Number(entry?.StartLine ?? 0),
  }));
}

/**
 * Build a finding from a parsed leak (no secret value).
 * @param {{ ruleId: string; description: string; file: string; line: number }} leak
 * @param {string} repoRoot
 * @param {TeardownFact | undefined} fact — catalog facts, when vendored.
 * @returns {Finding}
 */
function toFinding(leak, repoRoot, fact) {
  const repoFile = repoRelative(leak.file, repoRoot);
  const line = leak.line > 0 ? leak.line : null;
  const ruleId = leak.ruleId || 'unknown';

  // A secret in a conventional config file (parameters.yaml / database.yaml /
  // config/) is the framework's documented placement — flag it as an advisory,
  // never score it as a code defect.
  if (isSecretConfigFile(repoFile)) {
    return {
      id: `gitleaks:${repoFile}:${line ?? 0}:${ruleId}`,
      kind: 'hygiene',
      file: repoFile,
      line,
      column: null,
      severity: 'low',
      pillar: 'security',
      teardownId: null,
      advisory: true,
      title: 'Committed secret in config',
      message: leak.description || null,
      fixSummary:
        'Conventional secret placement — ensure the repo stays private (or gitignore this file) and rotate the value if the repo was ever public.',
      source: { provider: 'gitleaks', ruleId: leak.ruleId },
      dependency: null,
    };
  }

  const clientExposed = isClientExposed(repoFile);
  return {
    id: `gitleaks:${repoFile}:${line ?? 0}:${ruleId}`,
    kind: 'teardown',
    file: repoFile,
    line,
    column: null,
    severity: clientExposed ? fact?.severity ?? DEFAULTS.severity : 'high',
    pillar: fact?.pillar ?? DEFAULTS.pillar,
    teardownId: TEARDOWN_ID,
    title: `Hardcoded secret (${ruleId})`,
    message: leak.description || null,
    fixSummary: clientExposed
      ? fact?.fixSummary ?? DEFAULTS.fixSummary
      : 'Move the value to a server-side environment variable or secrets manager and rotate it — it is committed to git history.',
    source: { provider: 'gitleaks', ruleId: leak.ruleId },
    dependency: null,
  };
}

/**
 * Normalize a gitleaks `File` path to a repo-relative path (handles absolute sources).
 * @param {string} location
 * @param {string} repoRoot
 * @returns {string}
 */
function repoRelative(location, repoRoot) {
  if (isAbsolute(location)) {
    return relative(repoRoot, location).replace(/^[/\\]+/, '');
  }
  return location.replace(/^[/\\]+/, '');
}
