// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the report renderer (Markdown + LastMile deep-link).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixPath, renderMarkdown } from '../src/report.mjs';

test('fixPath builds a finding-ID deep-link (no code, no secrets)', () => {
  assert.equal(fixPath(['TD-008', 'TD-016']), 'https://peek.software/fix?findings=TD-008,TD-016');
  assert.equal(fixPath([]), 'https://peek.software/fix?findings=');
});

test('renderMarkdown renders the Last Mile handoff with the found teardown IDs', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 15, max: 350, tier: 'green', riskPercentage: 4 },
    pillars: [],
    findings: [
      { kind: 'teardown', teardownId: 'TD-008', file: 'src/a.ts', line: 1, title: 'lookup by id', source: { provider: 'semgrep', ruleId: 'r1' } },
      { kind: 'teardown', teardownId: 'TD-016', file: 'src/b.ts', line: 2, title: 'hardcoded secret', source: { provider: 'gitleaks', ruleId: 'generic-api-key' } },
      { kind: 'hygiene', teardownId: null, file: 'src/c.ts', line: 3, title: 'unused var', source: { provider: 'eslint', ruleId: 'no-unused-vars' } },
    ],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('https://peek.software/fix?findings=TD-008,TD-016'), markdown);
});

test('renderMarkdown lists dependency CVEs in a separate section, not in the code score', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 0, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [
      {
        kind: 'dependency',
        severity: 'critical',
        pillar: 'security',
        file: 'package-lock.json',
        line: null,
        title: 'proxy-addr vulnerable to IP spoofing',
        fixSummary: 'Upgrade proxy-addr beyond 2.0.7',
        source: { provider: 'osv', ruleId: 'CVE-2026-90711' },
        dependency: { package: 'proxy-addr', version: '2.0.7', ecosystem: 'npm', cveIds: ['CVE-2026-90711'] },
      },
    ],
    dependencies: { total: 1, critical: 1, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('## External Dependencies (CVEs)'), markdown);
  assert.ok(markdown.includes('proxy-addr'), markdown);
  assert.ok(markdown.includes('CVE-2026-90711'), markdown);
  // The dependency must NOT contribute to the code risk score.
  assert.ok(markdown.includes('Your code:** 0 / 350'), markdown);
});

test('renderMarkdown keeps a plain Last Mile line when there are no findings', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 0, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('- Get It Fixed by Last Mile'));
  assert.ok(!markdown.includes('/fix?findings='));
});

test('renderMarkdown explains each finding with its message and fix', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 2, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [
      {
        kind: 'teardown',
        teardownId: 'TD-002',
        file: 'src/ai.ts',
        line: 4,
        severity: 'critical',
        pillar: 'runtime',
        title: 'LLM call without a token cap',
        message: 'Output is unbounded and spend is unconstrained.',
        fixSummary: 'Cap max_tokens, require auth, and rate-limit per user.',
        source: { provider: 'semgrep', ruleId: 'peek-td-002' },
      },
    ],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('Output is unbounded and spend is unconstrained.'), markdown);
  assert.ok(markdown.includes('Fix: Cap max_tokens, require auth, and rate-limit per user.'), markdown);
});

test('renderMarkdown reports test-file findings separately and unscored', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 0, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [
      {
        kind: 'teardown',
        teardownId: 'TD-016',
        file: 'src/app.ts',
        line: 2,
        severity: 'critical',
        pillar: 'security',
        title: 'Hardcoded secret (aws-access-token)',
        source: { provider: 'gitleaks', ruleId: 'aws-access-token' },
      },
      {
        kind: 'teardown',
        teardownId: 'TD-016',
        file: 'src/keys.test.ts',
        line: 3,
        severity: 'critical',
        pillar: 'security',
        title: 'Hardcoded secret (aws-access-token)',
        source: { provider: 'gitleaks', ruleId: 'aws-access-token' },
        inTests: true,
      },
    ],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('## Findings in test files (not scored)'), markdown);
  assert.ok(markdown.includes('keys.test.ts'), markdown);
});
