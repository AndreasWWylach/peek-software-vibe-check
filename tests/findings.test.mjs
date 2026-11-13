// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for finding dedup + ordering.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dedupeFindings, sortFindings } from '../src/findings.mjs';

/** @typedef {import('../src/types.mjs').Finding} Finding */

/**
 * Build a minimal finding for tests.
 * @param {Partial<Finding>} [overrides]
 * @returns {Finding}
 */
function base(overrides = {}) {
  return /** @type {Finding} */ ({
    id: 't',
    kind: 'teardown',
    file: 'a.ts',
    line: 1,
    column: 1,
    severity: 'low',
    pillar: 'qa',
    teardownId: 'TD-045',
    title: 'test finding',
    message: null,
    fixSummary: null,
    source: { provider: 'test', ruleId: 'x' },
    dependency: null,
    ...overrides,
  });
}

test('dedupe collapses the same teardown on the same file:line, keeping max severity', () => {
  const a = base({ id: '1', severity: 'low' });
  const b = base({ id: '2', severity: 'critical' });
  const out = dedupeFindings([a, b]);
  assert.equal(out.length, 1);
  assert.equal(out[0].severity, 'critical');
});

test('dedupe unions CVE ids for the same package', () => {
  const a = /** @type {Finding} */ ({
    ...base(),
    kind: 'dependency',
    teardownId: null,
    dependency: { package: 'lodash', version: '4.0.0', ecosystem: 'npm', cveIds: ['CVE-1'] },
  });
  const b = /** @type {Finding} */ ({
    ...base(),
    id: '2',
    kind: 'dependency',
    teardownId: null,
    dependency: { package: 'lodash', version: '4.0.0', ecosystem: 'npm', cveIds: ['CVE-2'] },
  });
  const out = dedupeFindings([a, b]);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].dependency?.cveIds, ['CVE-1', 'CVE-2']);
});

test('sortFindings orders by pillar then severity', () => {
  const qa = base({ pillar: 'qa', severity: 'low' });
  const security = base({ id: '2', pillar: 'security', severity: 'medium' });
  const out = sortFindings([qa, security]);
  assert.equal(out[0].pillar, 'security');
  assert.equal(out[1].pillar, 'qa');
});
