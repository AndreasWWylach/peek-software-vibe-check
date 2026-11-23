// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for the shared secret classifier across providers —
 * semgrep TD-016 must agree with gitleaks/trivy on what is NOT a secret.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isClassifiedSecret } from '../src/providers/semgrep.mjs';

/** @param {string} file @param {number | null} line @param {string} [td]
 * @returns {import('../src/types.mjs').Finding} */
function tdFinding(file, line, td = 'TD-016') {
  return {
    id: 'x',
    kind: 'teardown',
    file,
    line,
    column: null,
    severity: 'critical',
    pillar: 'security',
    teardownId: td,
    title: 't',
    message: null,
    fixSummary: null,
    source: { provider: 'semgrep', ruleId: 'r' },
    dependency: null,
  };
}

test('semgrep TD-016 skips placeholder examples via the shared classifier', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-classify-'));
  try {
    writeFileSync(
      join(dir, 'secretClassify.mjs'),
      ' *   - Placeholder secrets (`sk_test_placeholder`, `changeme`, …).\n',
      'utf8',
    );
    assert.equal(isClassifiedSecret(tdFinding('secretClassify.mjs', 1), dir), true);

    // A real Stripe test key stays flagged.
    writeFileSync(join(dir, 'keys.ts'), "const stripe = 'sk_test_51Hq7abcdefghijklmnop';\n", 'utf8');
    assert.equal(isClassifiedSecret(tdFinding('keys.ts', 1), dir), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('semgrep TD-016 classification only applies to TD-016 with a line', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-classify-'));
  try {
    assert.equal(isClassifiedSecret(tdFinding('x.ts', 1, 'TD-033'), dir), false, 'non-TD-016 untouched');
    assert.equal(isClassifiedSecret(tdFinding('x.ts', null), dir), false, 'line-less findings untouched');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
