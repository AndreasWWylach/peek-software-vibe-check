// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Vendor the PHPStan framework extensions into
 * `rules/vendored/phpstan/` so the engine stays offline & deterministic.
 *
 * Framework apps normally need the matching extension installed in their OWN
 * `vendor/` (larastan, phpstan-symfony, phpstan-doctrine). This script builds a
 * tiny pinned Composer project for the **self-contained** extensions
 * (phpstan-symfony, phpstan-doctrine — their only runtime dep is `phpstan/phpstan`,
 * which the pinned PHAR already provides, so it is `replace`d) and commits the
 * result. The phpstan provider then loads them via `--autoload-file` + neon
 * `includes:` when the scanned app does not ship them itself.
 *
 * Larastan is deliberately NOT vendored: it requires the app's own Illuminate
 * (a Laravel container it boots), so a vendored copy would class-collide with
 * the app's framework version. It stays app-side only.
 *
 * Run to refresh:  node scripts/vendor-phpstan-extensions.mjs
 */
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';

/** Pinned extension versions (exact, for determinism). */
const PINNED = {
  'phpstan/phpstan-symfony': '2.1.1',
  'phpstan/phpstan-doctrine': '2.1.2',
};

/** The phpstan version the engine's PHAR provides (replaced, never installed). */
const PHPSTAN_VERSION = '2.3.1';

const DEST_ROOT = fileURLToPath(new URL('../rules/vendored/phpstan', import.meta.url));

const workDir = join(tmpdir(), `vibe-check-phpstan-ext-${Date.now()}`);
mkdirSync(workDir, { recursive: true });

const composerJson = {
  name: 'vibe-check/phpstan-extensions',
  description: 'Vendored PHPStan framework extensions for vibe-check (offline, deterministic)',
  require: { php: '^8.1', ...PINNED },
  replace: { 'phpstan/phpstan': PHPSTAN_VERSION },
  config: { 'allow-plugins': false, 'sort-packages': true },
};
writeFileSync(join(workDir, 'composer.json'), `${JSON.stringify(composerJson, null, 2)}\n`, 'utf8');

console.log(`installing ${Object.keys(PINNED).join(', ')} …`);
execFileSync('composer', ['install', '--no-dev', '--no-interaction', '--no-progress', '--prefer-dist'], {
  cwd: workDir,
  stdio: 'inherit',
});

// The composer project installs only `vendor/composer/` (autoloader) + the two
// `vendor/phpstan/*` packages — nothing else. Copy the whole `vendor/` tree.
rmSync(DEST_ROOT, { recursive: true, force: true });
mkdirSync(DEST_ROOT, { recursive: true });
cpSync(join(workDir, 'vendor'), join(DEST_ROOT, 'vendor'), { recursive: true });
if (existsSync(join(workDir, 'composer.lock'))) {
  cpSync(join(workDir, 'composer.lock'), join(DEST_ROOT, 'composer.lock'));
}

writeFileSync(
  join(DEST_ROOT, 'manifest.json'),
  `${JSON.stringify(
    {
      source: 'https://packagist.org',
      pinned: PINNED,
      phpstanVersion: PHPSTAN_VERSION,
      vendoredAt: new Date().toISOString().slice(0, 10),
    },
    null,
    2,
  )}\n`,
  'utf8',
);

rmSync(workDir, { recursive: true, force: true });
console.log(`vendored ${Object.keys(PINNED).length} PHPStan extensions to ${DEST_ROOT}`);
