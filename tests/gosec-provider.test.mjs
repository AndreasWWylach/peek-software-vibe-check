// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the gosec (Go) provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gosecProvider, parseGosecJson } from '../src/providers/gosec.mjs';
import { banditProvider } from '../src/providers/bandit.mjs';

test('parseGosecJson maps SQLi/shell TDs to teardowns, others to advisory hygiene', () => {
  const stdout = JSON.stringify({
    Issues: [
      { rule_id: 'G201', severity: 'HIGH', confidence: 'HIGH', details: 'SQL string formatting', file: '/repo/app.go', line: '9', column: '5' },
      { rule_id: 'G204', severity: 'MEDIUM', confidence: 'HIGH', details: 'Subprocess launched with variable', file: '/repo/app.go', line: '8', column: '10' },
      { rule_id: 'G104', severity: 'LOW', confidence: 'LOW', details: 'Errors unhandled', file: '/repo/app.go', line: '3', column: '1' },
    ],
  });

  const findings = parseGosecJson(stdout, '/repo');

  const sql = findings.find((f) => f.source.ruleId === 'G201');
  assert.equal(sql?.kind, 'teardown');
  assert.equal(sql?.teardownId, 'TD-033');
  assert.equal(sql?.severity, 'high');
  assert.equal(sql?.line, 9);

  const shell = findings.find((f) => f.source.ruleId === 'G204');
  assert.equal(shell?.teardownId, 'TD-042');
  assert.equal(shell?.kind, 'teardown');

  const generic = findings.find((f) => f.source.ruleId === 'G104');
  assert.equal(generic?.kind, 'hygiene');
  assert.equal(generic?.teardownId, null);
  assert.equal(generic?.advisory, true);
});

test('gosec applicable gates on the go language', () => {
  assert.equal(gosecProvider.applicable(makeConfig(['go'])), true);
  assert.equal(gosecProvider.applicable(makeConfig(['javascript'])), false);
});

test('mixed repos route bandit+gosec only when their language is present', () => {
  const mixed = makeConfig(['javascript', 'python', 'go']);
  assert.equal(banditProvider.applicable(mixed), true);
  assert.equal(gosecProvider.applicable(mixed), true);
});

/**
 * Minimal valid ScanConfig for provider-gating tests.
 * @param {string[]} languages
 * @returns {import('../src/types.mjs').ScanConfig}
 */
function makeConfig(languages) {
  return {
    version: 1,
    engine: '>=0.1.0',
    targets: ['src/'],
    languages,
    enabledRules: [],
    ruleParams: {},
    exclude: [],
    scoring: { weights: { security: 1, runtime: 1, architecture: 1, qa: 1 } },
    quiz: undefined,
  };
}
