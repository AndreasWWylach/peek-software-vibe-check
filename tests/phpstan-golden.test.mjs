// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview PHPStan golden test — runs the real `phpstan` binary over a
 * fixture with undefined method/class/function (the AI-hallucination class)
 * and asserts the provider maps only those. Skipped when `phpstan` is missing.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommandCapture } from '../src/proc.mjs';
import { parsePhpstanJson } from '../src/providers/phpstan.mjs';

const FIXTURE = fileURLToPath(new URL('./fixtures/phpstan/bad.php', import.meta.url));

const phpstanAvailable = commandAvailable('phpstan');
const skipReason = phpstanAvailable ? false : 'phpstan is not installed — e2e skipped';

test('phpstan golden: undefined method/class/function fire as QA advisories', { skip: skipReason }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-phpstan-golden-'));
  try {
    const neon = join(dir, 'phpstan.neon');
    writeFileSync(
      neon,
      [
        'parameters:',
        '    level: 5',
        '    paths:',
        `        - ${FIXTURE}`,
        `    tmpDir: ${join(dir, 'cache')}`,
        '',
      ].join('\n'),
      'utf8',
    );

    const { stdout } = runCommandCapture('phpstan', ['analyse', '-c', neon, '--no-progress', '--no-ansi', '--error-format=json']);
    const findings = parsePhpstanJson(stdout, fileURLToPath(new URL('./fixtures/phpstan', import.meta.url)));
    const ids = findings.map((f) => f.source.ruleId);

    assert.ok(ids.includes('method.notFound'), `expected method.notFound, got ${ids.join(', ')}`);
    assert.ok(ids.includes('class.notFound'), `expected class.notFound, got ${ids.join(', ')}`);
    assert.ok(ids.includes('function.notFound'), `expected function.notFound, got ${ids.join(', ')}`);
    for (const f of findings) {
      assert.equal(f.advisory, true);
      assert.equal(f.pillar, 'qa');
      assert.equal(f.kind, 'hygiene');
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
