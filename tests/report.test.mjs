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
      { kind: 'teardown', teardownId: 'TD-008', file: 'src/a.ts', line: 1, title: 'lookup by id' },
      { kind: 'teardown', teardownId: 'TD-016', file: 'src/b.ts', line: 2, title: 'hardcoded secret' },
      { kind: 'hygiene', teardownId: null, file: 'src/c.ts', line: 3, title: 'unused var', source: { provider: 'eslint', ruleId: 'no-unused-vars' } },
    ],
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('https://peek.software/fix?findings=TD-008,TD-016'), markdown);
});

test('renderMarkdown keeps a plain Last Mile line when there are no findings', () => {
  const report = {
    engine: { name: 'vibe-check', version: '0.1.0', commit: 'abc1234' },
    generatedAt: '2026-11-13T00:00:00.000Z',
    riskScore: { total: 0, max: 350, tier: 'green', riskPercentage: 0 },
    pillars: [],
    findings: [],
    skippedProviders: [],
    notStaticallyVerifiable: [],
  };

  const markdown = renderMarkdown(/** @type {any} */ (report));
  assert.ok(markdown.includes('- Get It Fixed by Last Mile'));
  assert.ok(!markdown.includes('/fix?findings='));
});
