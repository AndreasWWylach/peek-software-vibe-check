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

test('renderMarkdown links each teardown finding to its peek.software page', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 15, max: 350, tier: 'green', riskPercentage: 4 },
    pillars: [],
    findings: [
      { kind: 'teardown', teardownId: 'TD-008', pillar: 'security', severity: 'critical', file: 'src/a.ts', line: 1, title: 'lookup by id', source: { provider: 'semgrep', ruleId: 'r1' } },
      { kind: 'teardown', teardownId: 'TD-016', pillar: 'security', severity: 'critical', file: 'src/b.ts', line: 2, title: 'hardcoded secret', source: { provider: 'gitleaks', ruleId: 'generic-api-key' } },
      { kind: 'hygiene', teardownId: null, pillar: 'qa', severity: 'low', file: 'src/c.ts', line: 3, title: 'unused var', source: { provider: 'eslint', ruleId: 'no-unused-vars' } },
    ],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('https://peek.software/teardowns/TD-008'), markdown);
  assert.ok(markdown.includes('https://peek.software/teardowns/TD-016'), markdown);
  // The Last Mile hand-off block was removed from the report.
  assert.ok(!markdown.includes('https://peek.software/fix?findings='), markdown);
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

test('renderMarkdown no longer emits a Next Steps block', () => {
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
  assert.ok(!markdown.includes('## Next Steps'), markdown);
  assert.ok(!markdown.includes('Get It Fixed by Last Mile'), markdown);
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
  // The summary table must attribute the test-file count to its provider.
  assert.ok(markdown.includes('| gitleaks | 1 · 1 in tests | TD-016 ×1 · test files: TD-016 ×1 |'), markdown);
});

test('renderMarkdown reports advisory findings separately and unscored', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 0, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [
      {
        kind: 'teardown',
        teardownId: 'TD-016',
        file: 'src/keys.ts',
        line: 2,
        severity: 'critical',
        pillar: 'security',
        title: 'Hardcoded secret (aws-access-token)',
        source: { provider: 'gitleaks', ruleId: 'aws-access-token' },
      },
      {
        kind: 'hygiene',
        teardownId: null,
        file: 'config/parameters.yaml',
        line: 2,
        severity: 'low',
        pillar: 'security',
        title: 'Committed secret in config',
        source: { provider: 'gitleaks', ruleId: 'generic-api-key' },
        advisory: true,
      },
    ],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('## Advisories (not scored)'), markdown);
  assert.ok(markdown.includes('Committed secret in config'), markdown);
  assert.ok(markdown.includes('parameters.yaml'), markdown);
  // The advisory must NOT appear in the scored "Findings (your code)" section —
  // it is its own unscored section. Verify by checking the section order.
  assert.ok(markdown.indexOf('## Advisories (not scored)') > markdown.indexOf('## Findings (your code)'), markdown);
});

test('renderMarkdown groups same-rule advisories under one message with the files listed', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 0, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [
      { kind: 'hygiene', teardownId: null, file: 'a.php', line: 1, severity: 'low', pillar: 'security', title: 'Use of exec() function.', source: { provider: 'semgrep', ruleId: 'vendored.exec-use' }, advisory: true },
      { kind: 'hygiene', teardownId: null, file: 'b.php', line: 2, severity: 'low', pillar: 'security', title: 'Use of exec() function.', source: { provider: 'semgrep', ruleId: 'vendored.exec-use' }, advisory: true },
      { kind: 'hygiene', teardownId: null, file: 'c.php', line: 3, severity: 'low', pillar: 'security', title: 'Use of exec() function.', source: { provider: 'semgrep', ruleId: 'vendored.exec-use' }, advisory: true },
    ],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  // One grouped bullet, not three: header with title + count, then compact file
  // locations.
  assert.ok(markdown.includes('- 💡 **vendored.exec-use** — Use of exec() function. (3)'), markdown);
  assert.ok(markdown.includes('`a.php:1`'), markdown);
  assert.ok(markdown.includes('`b.php:2`'), markdown);
  assert.ok(markdown.includes('`c.php:3`'), markdown);
});

test('renderMarkdown renders a brief App Stack summary from detected markers', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 0, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
    stack: { firebase: true, firestore: true, cloudFunctions: true, react: true, stripe: true },
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('## App Stack'), markdown);
  assert.ok(markdown.includes('Firestore database'), markdown);
  assert.ok(markdown.includes('Cloud Functions'), markdown);
  assert.ok(markdown.includes('Stripe payments'), markdown);
});

test('renderMarkdown omits the App Stack section when no markers were detected', () => {
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
  assert.ok(!markdown.includes('## App Stack'), markdown);
});

test('renderMarkdown surfaces disabled checks so a low score is not read as all-clear', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 0, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    disabledChecks: [{ id: 'scc:TD-019', detail: 'monolithic-file detection is opt-in — set `ruleParams.maxFileLines`.' }],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('## Disabled Checks'), markdown);
  assert.ok(markdown.includes('scc:TD-019'), markdown);
  assert.ok(markdown.includes('were not scored'), markdown);
});

test('renderMarkdown reports Pimcore as Twig, not React (admin UI is not the frontend)', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 0, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [],
    dependencies: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    skippedProviders: [],
    notStaticallyVerifiable: [],
    stack: { pimcore: true, symfony: true, doctrine: true, react: true },
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('Pimcore (Symfony)'), markdown);
  assert.ok(markdown.includes('Twig templates'), markdown);
  assert.ok(markdown.includes('Doctrine ORM'), markdown);
  assert.ok(!markdown.includes('React frontend'), markdown);
});
