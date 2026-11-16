// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Vendor the Semgrep PHP rulesets into `rules/vendored/php/`.
 *
 * The engine must stay **offline & deterministic**, so the community PHP packs
 * are pinned and committed here rather than downloaded from the Semgrep
 * Registry at scan time. Run this script to refresh them:
 *
 *   node scripts/vendor-php-rules.mjs
 *
 * It shallow-clones semgrep/semgrep-rules at the pinned SHA, copies the PHP
 * rule YAML files (skipping Semgrep's own `.php` test fixtures and any
 * `.test.yaml`), and writes `manifest.json` (source, SHA, date) that
 * `vibe-check doctor` uses to warn about stale rulesets.
 */
import { cpSync, mkdirSync, readdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';

/** The pinned upstream commit (semgrep/semgrep-rules, `develop`). */
const PINNED_SHA = 'a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2';
const SOURCE_REPO = 'https://github.com/semgrep/semgrep-rules.git';
const DEST_ROOT = fileURLToPath(new URL('../rules/vendored/php', import.meta.url));

/** Upstream dir → vendored dir (relative to `rules/vendored/php`). */
const PACKS = [
  ['php/lang', 'lang'],
  ['php/laravel/security', 'laravel'],
  ['php/symfony/security', 'symfony'],
  ['php/doctrine/security', 'doctrine'],
  ['php/wordpress-plugins/security', 'wordpress'],
];

/**
 * Copy a directory of rule YAML files (only `.yaml`, never `.test.yaml`, never
 * Semgrep's `.php` fixtures).
 * @param {string} from
 * @param {string} to
 */
function copyRuleDir(from, to) {
  mkdirSync(to, { recursive: true });
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    const src = join(from, entry.name);
    const dst = join(to, entry.name);
    if (entry.isDirectory()) {
      copyRuleDir(src, dst);
    } else if (entry.isFile() && entry.name.endsWith('.yaml') && !entry.name.endsWith('.test.yaml')) {
      cpSync(src, dst);
    }
  }
}

const workDir = join(tmpdir(), `vibe-check-semgrep-rules-${PINNED_SHA.slice(0, 8)}`);
if (!existsSync(join(workDir, 'php'))) {
  console.log(`cloning ${SOURCE_REPO} @ ${PINNED_SHA} …`);
  rmSync(workDir, { recursive: true, force: true });
  mkdirSync(workDir, { recursive: true });
  execFileSync('git', ['clone', '--depth', '1', SOURCE_REPO, workDir], { stdio: 'inherit' });
  execFileSync('git', ['-C', workDir, 'checkout', PINNED_SHA], { stdio: 'inherit' });
}

rmSync(DEST_ROOT, { recursive: true, force: true });
mkdirSync(DEST_ROOT, { recursive: true });
for (const [src, dst] of PACKS) {
  const from = join(workDir, src);
  if (!existsSync(from)) {
    console.warn(`warning: missing upstream dir ${src} — skipped`);
    continue;
  }
  copyRuleDir(from, join(DEST_ROOT, dst));
}

writeFileSync(
  join(DEST_ROOT, 'manifest.json'),
  JSON.stringify(
    {
      source: SOURCE_REPO,
      pinnedSha: PINNED_SHA,
      vendoredAt: new Date().toISOString().slice(0, 10),
      packs: PACKS.map(([, dst]) => dst),
    },
    null,
    2,
  ) + '\n',
  'utf8',
);

console.log(`vendored ${PACKS.length} PHP packs to ${DEST_ROOT}`);
