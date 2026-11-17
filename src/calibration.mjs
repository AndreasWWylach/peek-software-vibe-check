// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Calibration overlay — self-report (quiz) vs. scan comparison.
 *
 * When the config carries quiz data, the report shows the "calibration moment"
 * (docs §3 level 2): what the user CLAIMED in the quiz vs. what the scan
 * OBJECTIVELY found. Pure and deterministic — it takes the catalog facts as an
 * argument so it stays unit-testable without touching disk or the network.
 */
import { PILLAR_ORDER } from './scoring.mjs';

/** @typedef {import('./types.mjs').Pillar} Pillar */
/** @typedef {import('./types.mjs').Finding} Finding */
/** @typedef {import('./types.mjs').PillarScore} PillarScore */
/** @typedef {import('./types.mjs').Calibration} Calibration */

/**
 * Compute the calibration overlay, or null when no quiz data is present.
 * @param {{
 *   quiz?: Record<string, unknown>;
 *   scanTotal: number;
 *   scanPillars: PillarScore[];
 *   findings: Finding[];
 *   teardownFacts: Array<{ id: string; mappedQuestion?: string | null }>;
 * }} input
 * @returns {Calibration | null}
 */
export function computeCalibration({ quiz, scanTotal, scanPillars, findings, teardownFacts }) {
  if (!quiz || typeof quiz.totalScore !== 'number') return null;

  const selfReport = quiz.totalScore;
  const pillarBreakdown =
    quiz.pillarBreakdown && typeof quiz.pillarBreakdown === 'object'
      ? /** @type {Record<string, number>} */ (quiz.pillarBreakdown)
      : {};
  const hotspots = Array.isArray(quiz.hotspots)
    ? quiz.hotspots.filter((hotspot) => typeof hotspot === 'string')
    : [];

  const scanByPillar = new Map(scanPillars.map((pillar) => [pillar.pillar, pillar.score]));

  /** @type {Array<{ pillar: Pillar; selfReport: number; scan: number }>} */
  const pillars = PILLAR_ORDER.map((pillar) => ({
    pillar,
    selfReport: pillarBreakdown[pillar] ?? 0,
    scan: scanByPillar.get(pillar) ?? 0,
  }));

  // Reverse index: quiz question id → teardown ids. One question may map to
  // several teardowns (e.g. Q3.1 covers both TD-019 monolithic + TD-021
  // circular), so this is many-to-one, not one-to-one.
  /** @type {Map<string, string[]>} */
  const questionToTds = new Map();
  for (const fact of teardownFacts) {
    if (fact.mappedQuestion) {
      const ids = questionToTds.get(fact.mappedQuestion) ?? [];
      ids.push(fact.id);
      questionToTds.set(fact.mappedQuestion, ids);
    }
  }

  /** @type {Set<string>} */
  const foundTds = new Set();
  for (const finding of findings) {
    if (finding.kind === 'teardown' && finding.teardownId) foundTds.add(finding.teardownId);
  }

  /** @type {Array<{ questionId: string; teardownIds: string[]; found: string[] }>} */
  const moments = hotspots.map((questionId) => {
    const teardownIds = questionToTds.get(questionId) ?? [];
    const found = teardownIds.filter((id) => foundTds.has(id));
    return { questionId, teardownIds, found };
  });

  return { selfReport, scan: scanTotal, pillars, moments };
}
