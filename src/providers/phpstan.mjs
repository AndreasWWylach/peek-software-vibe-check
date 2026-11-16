// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview PHPStan provider — PHP static analysis (deep mode, opt-in).
 *
 * PHPStan catches entire categories Semgrep cannot: undefined classes/methods
 * (the hallmark of AI hallucination), type mismatches, and contract violations.
 * It is **not** a security teardown source — findings map to the QA pillar as
 * advisories (reported, unscored).
 *
 * Gating (offline, deterministic — a pinned PHAR + the project's own autoloader):
 * - runs only when `vendor/autoload.php` exists (a composer-installed app);
 * - plain PHP apps run at level 5 with no extension needed;
 * - framework apps run only when the matching extension is in `vendor/`
 *   (larastan for Laravel, phpstan-symfony for Symfony/Pimcore,
 *   phpstan-doctrine for Doctrine) — otherwise skipped with a note, because
 *   framework magic (facades/DI) floods level-5 analysis with false positives.
 *
 * A minimal neon is generated in the OS temp dir (absolute paths, never written
 * into the user's repo): level 5, the config targets as `paths`, and the
 * Pimcore dynamic-constants stub when present. PHPStan auto-discovers the
 * vendor extensions via extension-installer.
 *
 * Only the **hallucination class** is reported (`*.notFound` / `*.undefined`
 * identifiers — undefined classes/methods/functions): style rules (e.g.
 * ergebnis/*) and type-mismatch flood a real framework app with noise and are
 * dropped. This keeps the QA advisory section a sharp signal, not a dump.
 */
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { commandAvailable, runCommandCapture } from '../proc.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */

/** Framework marker → vendor dir of the matching phpstan extension. */
const FRAMEWORK_EXTENSIONS = /** @type {Record<string, string>} */ ({
  laravel: 'larastan/larastan',
  symfony: 'phpstan/phpstan-symfony',
  pimcore: 'phpstan/phpstan-symfony',
  doctrine: 'phpstan/phpstan-doctrine',
});

/** Identifiers that are the high-signal "hallucination" class (undefined X). */
const PHPSTAN_KEEP_RE = /(method|class|function|property|constant|variable|trait|interface)\.(notFound|undefined)/;

/**
 * The phpstan error identifier for a message, falling back to message-derived
 * ids when the `identifier` field is absent (older phpstan).
 * @param {Record<string, any>} msg
 * @returns {string}
 */
export function phpstanIdentifier(msg) {
  const id = String(msg.identifier ?? '');
  if (id) return id;
  const m = String(msg.message ?? '');
  if (/undefined method/i.test(m)) return 'method.notFound';
  if (/undefined property/i.test(m)) return 'property.notFound';
  if (/function .*not found/i.test(m)) return 'function.notFound';
  if (/class .*not found/i.test(m)) return 'class.notFound';
  return 'phpstan';
}

/** @type {Provider} */
export const phpstanProvider = {
  id: 'phpstan',
  name: 'PHPStan (PHP)',
  available: () => commandAvailable('phpstan'),
  applicable: (config) => config.languages.some((lang) => lang.toLowerCase() === 'php'),
  async run(config, ctx) {
    const autoload = join(ctx.repoRoot, 'vendor', 'autoload.php');
    if (!existsSync(autoload)) {
      ctx.log('  no vendor/autoload.php — skipping (not a composer-installed app)');
      return [];
    }

    const stack = ctx.stack ?? {};
    const frameworks = Object.keys(FRAMEWORK_EXTENSIONS).filter((marker) => stack[marker]);
    if (frameworks.length > 0) {
      const missing = frameworks
        .map((marker) => FRAMEWORK_EXTENSIONS[marker])
        .filter((ext) => !existsSync(join(ctx.repoRoot, 'vendor', ...ext.split('/'))))
        .filter((ext, i, arr) => arr.indexOf(ext) === i);
      if (missing.length > 0) {
        ctx.log(`  skipping: framework detected but phpstan extension missing (${missing.join(', ')})`);
        return [];
      }
    }

    const neon = writeNeon(ctx, stack);
    try {
      const { stdout } = runCommandCapture(
        'phpstan',
        ['analyse', '-c', neon, '--no-progress', '--no-ansi', '--error-format=json'],
        { cwd: ctx.repoRoot },
      );
      return parsePhpstanJson(stdout, ctx.repoRoot);
    } finally {
      rmSync(dirname(neon), { recursive: true, force: true });
    }
  },
};

/**
 * Generate a minimal phpstan neon in the OS temp dir (absolute paths only).
 * @param {RunContext} ctx
 * @param {Record<string, boolean>} stack
 * @returns {string} absolute path to the generated `.neon` file.
 */
function writeNeon(ctx, stack) {
  const existing = ctx.targets.filter((target) => existsSync(target));
  const scanDir = mkdtempSync(join(tmpdir(), 'vibe-check-phpstan-'));

  /** @type {string[]} */
  const lines = ['parameters:', '    level: 5', '    paths:'];
  for (const target of existing) lines.push(`        - ${target}`);
  lines.push(`    tmpDir: ${join(scanDir, 'cache')}`);
  lines.push('    reportUnmatchedIgnoredErrors: false');
  lines.push('');

  // Pimcore ships a stub for its dynamic constants — required for precision.
  if (stack.pimcore) {
    const stub = join(ctx.repoRoot, 'vendor', 'pimcore', 'pimcore', 'stubs', 'dynamic-constants.php');
    if (existsSync(stub)) {
      lines.splice(lines.indexOf('    reportUnmatchedIgnoredErrors: false'), 0, '    scanFiles:', `        - ${stub}`);
    }
  }

  const neon = join(scanDir, 'phpstan.neon');
  writeFileSync(neon, `${lines.join('\n')}\n`, 'utf8');
  return neon;
}

/**
 * Parse `phpstan --error-format=json` into QA advisory findings.
 * @param {string} stdout
 * @param {string} repoRoot
 * @returns {Finding[]}
 */
export function parsePhpstanJson(stdout, repoRoot) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  const files = /** @type {Record<string, Record<string, any>> | undefined} */ (parsed?.files);
  if (!files || typeof files !== 'object') return [];

  /** @type {Finding[]} */
  const findings = [];
  for (const [absPath, file] of Object.entries(files)) {
    const messages = /** @type {Array<Record<string, any>> | undefined} */ (file?.messages);
    if (!Array.isArray(messages)) continue;
    for (const msg of messages) {
      const identifier = phpstanIdentifier(msg);
      if (!PHPSTAN_KEEP_RE.test(identifier)) continue;
      findings.push(toFinding(absPath, msg, identifier, repoRoot));
    }
  }
  return findings;
}

/**
 * Convert one phpstan message into a QA advisory finding.
 * @param {string} absPath
 * @param {Record<string, any>} msg
 * @param {string} ruleId — the phpstan error identifier (e.g. `method.notFound`).
 * @param {string} repoRoot
 * @returns {Finding}
 */
function toFinding(absPath, msg, ruleId, repoRoot) {
  const file = absPath.startsWith(repoRoot)
    ? absPath.slice(repoRoot.length).replace(/^[/\\]+/, '')
    : absPath.replace(/^[/\\]+/, '');
  const message = String(msg.message ?? '');
  const line = typeof msg.line === 'number' ? /** @type {number} */ (msg.line) : null;
  const severity = /** @type {Severity} */ ('medium');

  return {
    id: `phpstan:${ruleId}:${file}:${line ?? 0}`,
    kind: 'hygiene',
    file,
    line,
    column: null,
    severity,
    pillar: 'qa',
    teardownId: null,
    title: message,
    message: null,
    fixSummary: null,
    source: { provider: 'phpstan', ruleId },
    dependency: null,
    advisory: true,
  };
}
