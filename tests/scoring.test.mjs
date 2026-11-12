// @ts-check
/**
 * @fileoverview Unit tests for the scoring model.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getRiskTier, computeScores, MAX_TOTAL_SCORE, PILLAR_MAX_SCORES } from '../src/scoring.mjs';

/** @typedef {import('../src/types.mjs').Finding} Finding */
/** @typedef {import('../src/types.mjs').Pillar} Pillar */
/** @typedef {import('../src/types.mjs').Severity} Severity */

/**
 * Build a minimal teardown finding for tests.
 * @param {{ pillar?: Pillar; severity?: Severity }} [overrides]
 * @returns {Finding}
 */
function finding(overrides = {}) {
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

test('getRiskTier respects green ≤17 / amber ≤46 / red >46 boundaries', () => {
  assert.equal(getRiskTier(0), 'green');
  assert.equal(getRiskTier(17), 'green');
  assert.equal(getRiskTier(18), 'amber');
  assert.equal(getRiskTier(46), 'amber');
  assert.equal(getRiskTier(47), 'red');
  assert.equal(getRiskTier(100), 'red');
});

test('computeScores caps per-pillar and total', () => {
  const findings = [
    ...Array.from({ length: 50 }, () => finding({ pillar: 'security', severity: 'critical' })),
    ...Array.from({ length: 50 }, () => finding({ pillar: 'runtime', severity: 'critical' })),
    ...Array.from({ length: 50 }, () => finding({ pillar: 'architecture', severity: 'critical' })),
    ...Array.from({ length: 50 }, () => finding({ pillar: 'qa', severity: 'critical' })),
  ];
  const result = computeScores(findings);
  assert.equal(result.pillars[0].score, PILLAR_MAX_SCORES.security);
  assert.equal(result.total, MAX_TOTAL_SCORE);
  assert.equal(result.tier, 'red');
});

test('a critical finding forces the tier above green', () => {
  // One critical = 20 points → ~6% → would otherwise be green.
  const result = computeScores([finding({ pillar: 'qa', severity: 'critical' })]);
  assert.equal(result.tier, 'amber');
});

test('no findings → score 0 and green', () => {
  const result = computeScores([]);
  assert.equal(result.total, 0);
  assert.equal(result.riskPercentage, 0);
  assert.equal(result.tier, 'green');
});
