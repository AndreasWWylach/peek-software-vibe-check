// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for the AI remediation-prompt generator.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { groupRemediationFindings, renderFixPrompts } from '../src/fix-prompts.mjs';

/** @type {import('../src/types.mjs').Report} */
const BASE_REPORT = {
  schemaVersion: 1,
  engine: { name: 'vibe-check', version: '0.1.0', commit: null },
  generatedAt: '2026-11-22T12:00:00.000Z',
  riskScore: { total: 30, max: 350, tier: 'amber', riskPercentage: 9 },
  pillars: [],
  findings: [],
  dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
  skippedProviders: [],
  disabledChecks: [],
  notStaticallyVerifiable: [],
  calibration: undefined,
};

/**
 * Build a minimal finding.
 * @param {Partial<import('../src/types.mjs').Finding> & Pick<import('../src/types.mjs').Finding, 'kind' | 'title'>} input
 * @returns {import('../src/types.mjs').Finding}
 */
function finding(input) {
  return {
    id: input.id ?? `id-${Math.random()}`,
    file: input.file ?? 'src/x.ts',
    line: input.line ?? null,
    column: null,
    severity: input.severity ?? 'medium',
    pillar: input.pillar ?? 'security',
    teardownId: input.teardownId ?? null,
    message: input.message ?? null,
    fixSummary: input.fixSummary ?? null,
    source: input.source ?? { provider: 'semgrep', ruleId: 'rule-x' },
    dependency: input.dependency ?? null,
    ...input,
  };
}

test('groupRemediationFindings groups teardown findings by (teardownId, title)', () => {
  const groups = groupRemediationFindings([
    finding({ kind: 'teardown', teardownId: 'TD-033', title: 'SQL concat', file: 'src/a.ts', line: 10 }),
    finding({ kind: 'teardown', teardownId: 'TD-033', title: 'SQL concat', file: 'src/b.ts', line: 20 }),
    finding({ kind: 'teardown', teardownId: 'TD-042', title: 'Command injection', file: 'src/c.ts', line: 5 }),
  ]);
  assert.equal(groups.length, 2);
  assert.deepEqual(groups.map((g) => g.teardownId).sort(), ['TD-033', 'TD-042']);
  assert.equal(groups.find((g) => g.teardownId === 'TD-033')?.locations.length, 2);
});

test('groupRemediationFindings collapses dependency CVEs into one group', () => {
  const groups = groupRemediationFindings([
    finding({
      kind: 'dependency', title: 'CVE-1', severity: 'critical', file: 'package-lock.json',
      dependency: { package: 'undici', version: '6.0.0', ecosystem: 'npm', cveIds: ['CVE-A'] },
    }),
    finding({
      kind: 'dependency', title: 'CVE-2', severity: 'high', file: 'package-lock.json',
      dependency: { package: 'axios', version: '1.0.0', ecosystem: 'npm', cveIds: ['CVE-B', 'CVE-C'] },
    }),
    finding({ kind: 'teardown', teardownId: 'TD-016', title: 'Hardcoded secret', severity: 'high', file: 'src/k.ts', line: 3 }),
  ]);
  assert.equal(groups.length, 2);
  const dep = groups.find((g) => g.kind === 'dependency');
  assert.ok(dep);
  assert.equal(dep.packages.length, 2);
  assert.equal(dep.severity, 'critical'); // highest wins
  assert.equal(dep.title, 'Upgrade dependencies with known CVEs'); // not the first CVE's title
  // Severity ordering: critical dependency group first.
  assert.equal(groups[0].kind, 'dependency');
});

test('groupRemediationFindings groups hygiene by ruleId and keeps advisory flags', () => {
  const groups = groupRemediationFindings([
    finding({ kind: 'hygiene', title: 'XSS dom write', source: { provider: 'semgrep', ruleId: 'xss-dom-write' }, advisory: true }),
    finding({ kind: 'hygiene', title: 'XSS dom write', source: { provider: 'semgrep', ruleId: 'xss-dom-write' }, advisory: true }),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].advisory, true);
  assert.equal(groups[0].locations.length, 2);
});

test('renderFixPrompts includes evidence, fix, teardown link and verification', () => {
  const report = {
    ...BASE_REPORT,
    findings: [
      finding({
        kind: 'teardown', teardownId: 'TD-033', title: 'SQL concat',
        severity: 'critical', file: 'src/db/users.ts', line: 45,
        message: 'SQL assembled by string concatenation.',
        fixSummary: 'Pass values as placeholders.',
      }),
    ],
  };
  const { markdown, count } = renderFixPrompts(report);
  assert.equal(count, 1);
  assert.ok(markdown.includes('TD-033: SQL concat'), 'group heading with TD id');
  assert.ok(markdown.includes('src/db/users.ts:45'), 'file:line evidence');
  assert.ok(markdown.includes('Pass values as placeholders.'), 'fixSummary');
  assert.ok(markdown.includes('https://peek.software/teardowns/TD-033'), 'teardown deep link');
  assert.ok(markdown.includes('vibe-check run --config'), 're-run verification instruction');
  assert.ok(markdown.includes('## Checklist (1 fixes)'), 'master checklist');
});

test('renderFixPrompts handles reports without findings', () => {
  const { markdown, count } = renderFixPrompts({ ...BASE_REPORT, findings: [] });
  assert.equal(count, 0);
  assert.ok(markdown.includes('No actionable findings'));
});
