// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Scoring model — frozen constants shared with the peek.software quiz.
 *
 * Direction: higher = riskier, matching the quiz. Findings contribute
 * severity-based points to their pillar; pillar scores are capped at the
 * quiz's pillar maxima and the total is capped at MAX_TOTAL_SCORE.
 * Criticals impose a hard floor: any critical finding prevents a "green" tier.
 *
 * NOTE: the quiz has no per-finding point value (points live on quiz options,
 * 0–10). SEVERITY_POINTS below is the scan-side calibration — a first cut to
 * be re-validated in Phase 2 once the golden rules show real distributions.
 */

/** @typedef {import('./types.mjs').Pillar} Pillar */
/** @typedef {import('./types.mjs').Severity} Severity */
/** @typedef {import('./types.mjs').Tier} Tier */
/** @typedef {import('./types.mjs').Finding} Finding */
/** @typedef {import('./types.mjs').PillarScore} PillarScore */

/** Maximum total risk score (0–350), shared with the quiz. */
export const MAX_TOTAL_SCORE = 350;

/** Human-readable labels per pillar, shared with the quiz. */
export const PILLAR_LABELS = Object.freeze({
  security: 'Security & Secret Hygiene',
  runtime: 'Runtime Behavior & Infrastructure',
  architecture: 'Software Design & Architecture',
  qa: 'Testing & Quality Assurance',
});

/** Max points per pillar, shared with the quiz. */
export const PILLAR_MAX_SCORES = Object.freeze({
  security: 90,
  runtime: 90,
  architecture: 90,
  qa: 80,
});

/** Pillar display order, shared with the quiz. */
export const PILLAR_ORDER = /** @type {const} */ (['security', 'runtime', 'architecture', 'qa']);

/** Risk tier thresholds (percentage ≤), shared with the quiz. */
/** @type {Array<{ tier: Tier; maxPercent: number }>} */
const TIER_THRESHOLDS = [
  { tier: 'green', maxPercent: 17 },
  { tier: 'amber', maxPercent: 46 },
  { tier: 'red', maxPercent: 100 },
];

/**
 * Scan-side severity → points calibration (see the module NOTE above).
 */
export const SEVERITY_POINTS = Object.freeze({
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
});

/** Ordinal rank per severity, for dedup/ordering (higher = worse). */
export const SEVERITY_RANK = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
});

/**
 * Ordinal severity rank (4 = critical … 1 = low).
 * @param {Severity} severity
 * @returns {number}
 */
export function severityRank(severity) {
  return SEVERITY_RANK[severity];
}

/**
 * Classify a risk percentage into green/amber/red.
 * @param {number} riskPercentage — 0–100.
 * @returns {Tier}
 */
export function getRiskTier(riskPercentage) {
  for (const { tier, maxPercent } of TIER_THRESHOLDS) {
    if (riskPercentage <= maxPercent) return tier;
  }
  return 'red';
}

/**
 * Points contributed by a single finding of the given severity.
 * @param {Severity} severity
 * @returns {number}
 */
export function severityPoints(severity) {
  return SEVERITY_POINTS[severity];
}

/**
 * Summarize dependency (CVE) findings by severity.
 *
 * Dependencies are reported separately from the code risk score: a CVE is a
 * different remediation ("upgrade this package") than a code flaw ("rewrite
 * this logic"), and the quiz's self-report score has no dependency axis.
 * @param {Finding[]} findings — any findings; only `kind === 'dependency'` count.
 * @returns {{ total: number; critical: number; high: number; medium: number; low: number }}
 */
export function summarizeDependencies(findings) {
  /** @type {Record<Severity, number>} */
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    if (finding.kind === 'dependency') counts[finding.severity] += 1;
  }
  return {
    total: counts.critical + counts.high + counts.medium + counts.low,
    critical: counts.critical,
    high: counts.high,
    medium: counts.medium,
    low: counts.low,
  };
}

/**
 * Compute per-pillar + total risk scores from findings.
 *
 * Pillar scores are capped at their maxima; the total is capped at
 * MAX_TOTAL_SCORE. Any critical finding forces the tier above "green".
 * @param {Finding[]} findings
 * @returns {{ total: number; max: number; tier: Tier; riskPercentage: number; pillars: PillarScore[] }}
 */
export function computeScores(findings) {
  /** @type {Record<Pillar, number>} */
  const raw = { security: 0, runtime: 0, architecture: 0, qa: 0 };
  for (const finding of findings) {
    raw[finding.pillar] += severityPoints(finding.severity);
  }

  let total = 0;
  const pillars = PILLAR_ORDER.map((pillar) => {
    const score = Math.min(raw[pillar], PILLAR_MAX_SCORES[pillar]);
    total += score;
    return /** @type {PillarScore} */ ({
      pillar,
      label: PILLAR_LABELS[pillar],
      score,
      max: PILLAR_MAX_SCORES[pillar],
    });
  });

  total = Math.min(total, MAX_TOTAL_SCORE);
  const riskPercentage = Math.round((total / MAX_TOTAL_SCORE) * 100);
  let tier = getRiskTier(riskPercentage);

  // Hard floor: a critical finding must never produce a "green" readiness tier.
  if (findings.some((finding) => finding.severity === 'critical') && tier === 'green') {
    tier = 'amber';
  }

  return { total, max: MAX_TOTAL_SCORE, tier, riskPercentage, pillars };
}
