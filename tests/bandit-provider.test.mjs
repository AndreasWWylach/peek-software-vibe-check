// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the Bandit (Python) provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { banditProvider, parseBanditJson } from '../src/providers/bandit.mjs';
import { enrichTeardowns } from '../src/catalog.mjs';

test('parseBanditJson maps SQLi/shell TDs to teardowns, others to advisory hygiene', () => {
  const stdout = JSON.stringify({
    results: [
      { test_id: 'B608', issue_severity: 'MEDIUM', issue_confidence: 'MEDIUM', issue_text: 'Possible SQL injection', filename: '/repo/app.py', line_number: 9 },
      { test_id: 'B602', issue_severity: 'HIGH', issue_confidence: 'HIGH', issue_text: 'subprocess with shell=True', filename: '/repo/app.py', line_number: 5 },
      { test_id: 'B404', issue_severity: 'LOW', issue_confidence: 'HIGH', issue_text: 'Consider subprocess import', filename: '/repo/app.py', line_number: 1 },
    ],
  });

  const findings = parseBanditJson(stdout, '/repo');

  const sql = findings.find((f) => f.source.ruleId === 'B608');
  assert.equal(sql?.kind, 'teardown');
  assert.equal(sql?.teardownId, 'TD-033');
  assert.equal(sql?.severity, 'medium');
  assert.equal(sql?.advisory, false);

  const shell = findings.find((f) => f.source.ruleId === 'B602');
  assert.equal(shell?.teardownId, 'TD-042');
  assert.equal(shell?.kind, 'teardown');

  const generic = findings.find((f) => f.source.ruleId === 'B404');
  assert.equal(generic?.kind, 'hygiene');
  assert.equal(generic?.teardownId, null);
  assert.equal(generic?.advisory, true);
});

test('bandit applicable gates on the python language', () => {
  assert.equal(banditProvider.applicable(makeConfig(['python'])), true);
  assert.equal(banditProvider.applicable(makeConfig(['javascript', 'typescript'])), false);
});

test('parseBanditJson drops noisy ids (B101 assert, B110 try-except-pass)', () => {
  const stdout = JSON.stringify({
    results: [
      { test_id: 'B101', issue_severity: 'LOW', issue_confidence: 'HIGH', issue_text: 'Use of assert detected', filename: '/repo/t.py', line_number: 3 },
      { test_id: 'B110', issue_severity: 'LOW', issue_confidence: 'HIGH', issue_text: 'Try, Except, Pass detected', filename: '/repo/t.py', line_number: 7 },
      { test_id: 'B602', issue_severity: 'HIGH', issue_confidence: 'HIGH', issue_text: 'subprocess', filename: '/repo/t.py', line_number: 10 },
    ],
  });

  const findings = parseBanditJson(stdout, '/repo');
  assert.deepEqual(findings.map((f) => f.source.ruleId), ['B602']);
});

test('enrichTeardowns replaces tool severity with catalog severity', async () => {
  const stdout = JSON.stringify({
    results: [
      { test_id: 'B602', issue_severity: 'HIGH', issue_confidence: 'HIGH', issue_text: 'subprocess', filename: '/repo/app.py', line_number: 5 },
    ],
  });

  const [finding] = parseBanditJson(stdout, '/repo');
  assert.ok(finding);
  assert.equal(finding.severity, 'high'); // tool severity before enrichment

  const [enriched] = await enrichTeardowns([finding]);
  assert.equal(enriched.severity, 'critical'); // TD-042 catalog severity
  assert.equal(enriched.pillar, 'security');
  assert.ok(enriched.fixSummary, 'fixSummary filled from the catalog');
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
