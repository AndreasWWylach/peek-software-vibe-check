// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the semgrep provider's result → finding mapping.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSemgrepJson } from '../src/providers/semgrep.mjs';

test('parseSemgrepJson maps hygiene + advisory metadata', () => {
  const repoRoot = '/repo';
  const stdout = JSON.stringify({
    results: [
      {
        check_id: 'rules.hygiene.peek-hygiene-xss-dom-write',
        path: '/repo/src/app.js',
        start: { line: 7, col: 3 },
        extra: {
          severity: 'ERROR',
          message: 'document.write injects raw HTML',
          metadata: {
            peek: {
              hygiene: true,
              ruleId: 'xss-dom-write',
              pillar: 'security',
              severity: 'medium',
              advisory: true,
              title: 'XSS — raw HTML injected into the DOM',
              fixSummary: 'Avoid document.write()',
            },
            category: 'security',
          },
        },
      },
      {
        check_id: 'rules.peek.TD-042.command-injection-php',
        path: '/repo/src/run.php',
        start: { line: 3, col: 1 },
        extra: {
          severity: 'ERROR',
          message: 'Command built from user input',
          metadata: {
            peek: {
              teardownId: 'TD-042',
              pillar: 'security',
              severity: 'critical',
              title: 'Command injection',
              fixSummary: 'Validate against an allowlist',
            },
            category: 'security',
          },
        },
      },
    ],
  });

  const findings = parseSemgrepJson(stdout, repoRoot);

  const hygiene = findings.find((f) => f.file === 'src/app.js');
  assert.ok(hygiene);
  assert.equal(hygiene.kind, 'hygiene');
  assert.equal(hygiene.teardownId, null);
  assert.equal(hygiene.source.ruleId, 'xss-dom-write');
  assert.equal(hygiene.advisory, true);

  const teardown = findings.find((f) => f.file === 'src/run.php');
  assert.ok(teardown);
  assert.equal(teardown.kind, 'teardown');
  assert.equal(teardown.teardownId, 'TD-042');
  assert.equal(teardown.source.ruleId, 'rules.peek.TD-042.command-injection-php');
  assert.equal(teardown.advisory, false);
});
