// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the calibration overlay (self-report vs. scan).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeCalibration } from '../src/calibration.mjs';

/** @typedef {import('../src/types.mjs').Finding} Finding */

/**
 * Build a minimal teardown finding.
 * @param {string} teardownId
 * @returns {Finding}
 */
function finding(teardownId) {
  return /** @type {Finding} */ ({
    id: `${teardownId}:a.ts:1`,
    kind: 'teardown',
    file: 'a.ts',
    line: 1,
    column: 1,
    severity: 'high',
    pillar: 'security',
    teardownId,
    title: 'test',
    message: null,
    fixSummary: null,
    source: { provider: 'semgrep', ruleId: 'r' },
    dependency: null,
  });
}

/** All four pillar scan scores (saturated example). */
const scanPillars = [
  { pillar: /** @type {const} */ ('security'), label: 'x', score: 20, max: 90 },
  { pillar: /** @type {const} */ ('runtime'), label: 'x', score: 0, max: 90 },
  { pillar: /** @type {const} */ ('architecture'), label: 'x', score: 15, max: 90 },
  { pillar: /** @type {const} */ ('qa'), label: 'x', score: 0, max: 80 },
];

test('returns null when no quiz data is present', () => {
  assert.equal(computeCalibration({ quiz: undefined, scanTotal: 10, scanPillars, findings: [], teardownFacts: [] }), null);
  assert.equal(computeCalibration({ quiz: {}, scanTotal: 10, scanPillars, findings: [], teardownFacts: [] }), null);
});

test('compares self-report and scan totals + pillar scores', () => {
  const calibration = computeCalibration({
    quiz: { totalScore: 142, pillarBreakdown: { security: 34, runtime: 51 } },
    scanTotal: 35,
    scanPillars,
    findings: [],
    teardownFacts: [],
  });
  assert.ok(calibration);
  assert.equal(calibration.selfReport, 142);
  assert.equal(calibration.scan, 35);
  const security = calibration.pillars.find((pillar) => pillar.pillar === 'security');
  assert.equal(security?.selfReport, 34);
  assert.equal(security?.scan, 20);
  const qa = calibration.pillars.find((pillar) => pillar.pillar === 'qa');
  assert.equal(qa?.selfReport, 0); // absent from pillarBreakdown
  assert.equal(qa?.scan, 0);
});

test('maps hotspots to found / not-found / uncovered teardowns', () => {
  const calibration = computeCalibration({
    quiz: { totalScore: 142, hotspots: ['Q2.2', 'Q1.1', 'Q9.9'] },
    scanTotal: 35,
    scanPillars,
    findings: [finding('TD-002')],
    teardownFacts: [
      { id: 'TD-002', mappedQuestion: 'Q2.2' },
      { id: 'TD-016', mappedQuestion: 'Q1.1' },
    ],
  });
  assert.ok(calibration);

  const found = calibration.moments.find((moment) => moment.questionId === 'Q2.2');
  assert.equal(found?.teardownId, 'TD-002');
  assert.equal(found?.found, true);

  const notFound = calibration.moments.find((moment) => moment.questionId === 'Q1.1');
  assert.equal(notFound?.teardownId, 'TD-016');
  assert.equal(notFound?.found, false);

  const uncovered = calibration.moments.find((moment) => moment.questionId === 'Q9.9');
  assert.equal(uncovered?.teardownId, null);
  assert.equal(uncovered?.found, false);
});
