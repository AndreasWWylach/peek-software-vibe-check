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
 * - framework apps need the matching extension (larastan for Laravel,
 *   phpstan-symfony for Symfony/Pimcore, phpstan-doctrine for Doctrine) — the
 *   app's own `vendor/` copy is used when present, else the engine's vendored
 *   copy (`rules/vendored/phpstan/`) is loaded via `--autoload-file` + neon
 *   `includes:`. Larastan is NOT vendored (it needs the app's Illuminate), so
 *   a Laravel app without larastan is skipped with a note.
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
import { fileURLToPath } from 'node:url';
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

/** Absolute root of the vendored PHPStan extensions (`rules/vendored/phpstan/`). */
const VENDORED_EXT_ROOT = fileURLToPath(new URL('../../rules/vendored/phpstan', import.meta.url));

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

/**
 * Resolve which framework extensions are loadable, and from where.
 *
 * Precedence: the app's own `vendor/` extension (version-accurate, loaded via
 * PHPStan's extension-installer) → the engine's vendored copy (loaded via
 * `--autoload-file` + neon `includes:`) → missing (skip with a note).
 *
 * @param {Record<string, boolean>} stack
 * @param {string} repoRoot
 * @returns {{ includes: string[]; autoloadFile: string | null; vendored: string[]; missing: string[] }}
 */
export function resolveExtensions(stack, repoRoot) {
  /** @type {string[]} absolute `extension.neon` + `rules.neon` to include. */
  const includes = [];
  /** @type {string[]} */
  const vendored = [];
  /** @type {string[]} */
  const missing = [];
  /** @type {Set<string>} dedupe by extension package name (pimcore + symfony share one). */
  const seen = new Set();

  for (const marker of Object.keys(FRAMEWORK_EXTENSIONS)) {
    if (!stack[marker]) continue;
    const ext = FRAMEWORK_EXTENSIONS[marker];
    if (seen.has(ext)) continue;
    seen.add(ext);

    // The app ships the extension itself — extension-installer auto-discovers it.
    if (existsSync(join(repoRoot, 'vendor', ...ext.split('/')))) continue;

    const vendoredDir = join(VENDORED_EXT_ROOT, 'vendor', ...ext.split('/'));
    if (existsSync(join(vendoredDir, 'extension.neon')) && existsSync(join(vendoredDir, 'rules.neon'))) {
      vendored.push(ext);
      includes.push(join(vendoredDir, 'extension.neon'), join(vendoredDir, 'rules.neon'));
    } else {
      missing.push(ext);
    }
  }

  const vendoredAutoload = join(VENDORED_EXT_ROOT, 'vendor', 'autoload.php');
  const autoloadFile = vendored.length > 0 && existsSync(vendoredAutoload) ? vendoredAutoload : null;
  return { includes, autoloadFile, vendored, missing };
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

    const { includes, autoloadFile, vendored, missing } = resolveExtensions(ctx.stack ?? {}, ctx.repoRoot);
    if (missing.length > 0) {
      ctx.log(`  skipping: framework detected but phpstan extension missing (${missing.join(', ')})`);
      return [];
    }
    if (vendored.length > 0) {
      ctx.log(`  using vendored phpstan extension(s): ${vendored.join(', ')}`);
    }

    const neon = writeNeon(ctx, includes);
    /** @type {string[]} */
    const args = ['analyse', '-c', neon, '--no-progress', '--no-ansi', '--error-format=json'];
    if (autoloadFile) args.push('--autoload-file', autoloadFile);
    try {
      const { stdout } = runCommandCapture('phpstan', args, { cwd: ctx.repoRoot });
      return parsePhpstanJson(stdout, ctx.repoRoot);
    } finally {
      rmSync(dirname(neon), { recursive: true, force: true });
    }
  },
};

/**
 * Generate a minimal phpstan neon in the OS temp dir (absolute paths only).
 * @param {RunContext} ctx
 * @param {string[]} includes — absolute `extension.neon`/`rules.neon` paths for vendored extensions.
 * @returns {string} absolute path to the generated `.neon` file.
 */
function writeNeon(ctx, includes) {
  const existing = ctx.targets.filter((target) => existsSync(target));
  const scanDir = mkdtempSync(join(tmpdir(), 'vibe-check-phpstan-'));

  /** @type {string[]} */
  const lines = ['parameters:', '    level: 5', '    paths:'];
  for (const target of existing) lines.push(`        - ${target}`);
  lines.push(`    tmpDir: ${join(scanDir, 'cache')}`);
  lines.push('    reportUnmatchedIgnoredErrors: false');

  // Pimcore ships a stub for its dynamic constants — required for precision.
  if (ctx.stack?.pimcore) {
    const stub = join(ctx.repoRoot, 'vendor', 'pimcore', 'pimcore', 'stubs', 'dynamic-constants.php');
    if (existsSync(stub)) {
      lines.splice(lines.indexOf('    reportUnmatchedIgnoredErrors: false'), 0, '    scanFiles:', `        - ${stub}`);
    }
  }

  // Vendored framework extensions. Absolute paths: the neon lives in a temp
  // dir, so relative `includes:` would not resolve against the vendored copy.
  if (includes.length > 0) {
    lines.push('', 'includes:');
    for (const file of includes) lines.push(`    - ${file}`);
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
