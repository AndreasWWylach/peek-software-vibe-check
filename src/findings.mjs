// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Finding dedup + deterministic ordering.
 *
 * Multiple providers can flag the same problem (Semgrep and Bandit both flag
 * `subprocess`). Dedup collapses these into one finding — same teardown id +
 * file + line, or the same dependency — keeping the highest severity and
 * unioning CVE ids, per the design doc's "precision over volume" requirement.
 */
import { severityRank } from './scoring.mjs';

/** @typedef {import('./types.mjs').Finding} Finding */
/** @typedef {import('./types.mjs').Pillar} Pillar */

/**
 * Build a stable dedup key for a finding.
 * - teardown: collapse the same TD on the same file:line.
 * - dependency: collapse the same package+ecosystem (CVEs merge).
 * - hygiene: collapse the same title on the same file:line.
 * @param {Finding} finding
 * @returns {string}
 */
export function dedupeKey(finding) {
  switch (finding.kind) {
    case 'dependency':
      return `dep:${finding.dependency?.package ?? finding.title}:${finding.dependency?.ecosystem ?? ''}`;
    case 'teardown':
      return `td:${finding.teardownId ?? finding.source.ruleId}:${finding.file}:${finding.line ?? ''}`;
    case 'hygiene':
    default:
      return `hy:${finding.file}:${finding.line ?? ''}:${finding.title}`;
  }
}

/**
 * Merge `incoming` into `existing` (highest severity wins; CVE ids union;
 * cross-provider agreement recorded in `corroboratedBy`).
 * @param {Finding} existing
 * @param {Finding} incoming
 */
function mergeInto(existing, incoming) {
  if (existing.source?.provider !== incoming.source?.provider) {
    const others = new Set(existing.corroboratedBy ?? []);
    others.add(incoming.source?.provider ?? 'unknown');
    existing.corroboratedBy = [...others].sort();
  }
  if (severityRank(incoming.severity) > severityRank(existing.severity)) {
    existing.severity = incoming.severity;
    existing.title = incoming.title;
    existing.message = incoming.message;
    existing.fixSummary = incoming.fixSummary;
  }
  if (existing.dependency && incoming.dependency) {
    const union = new Set([...existing.dependency.cveIds, ...incoming.dependency.cveIds]);
    existing.dependency.cveIds = [...union].sort();
  }
}

/**
 * Correlate overlapping findings across providers BEFORE dedup: when gitleaks
 * and trivy both flag the same secret at the same file:line, collapse them into
 * one finding annotated with `corroboratedBy` (cross-tool confirmation).
 *
 * Dependency (CVE) overlap is handled by `dedupeFindings` instead — trivy and
 * osv-scanner findings for the same package+ecosystem already merge there.
 * @param {Finding[]} findings
 * @returns {Finding[]} findings with secret overlaps collapsed.
 */
export function corroborateFindings(findings) {
  /** @type {Map<string, Finding>} */
  const byKey = new Map();
  /** @type {Finding[]} */
  const out = [];
  for (const finding of findings) {
    const key = secretCorrelationKey(finding);
    if (!key) {
      out.push(finding);
      continue;
    }
    const existing = byKey.get(key);
    if (existing && existing.source?.provider !== finding.source?.provider) {
      mergeInto(existing, finding);
    } else {
      byKey.set(key, finding);
      out.push(finding);
    }
  }
  return out;
}

/**
 * The cross-provider correlation key for a secret finding (null when N/A).
 * @param {Finding} finding
 * @returns {string | null}
 */
function secretCorrelationKey(finding) {
  const provider = finding.source?.provider;
  if (provider === 'gitleaks') return `secret:${finding.file}:${finding.line ?? 0}`;
  if (provider === 'trivy' && finding.kind === 'hygiene') return `secret:${finding.file}:${finding.line ?? 0}`;
  return null;
}

/**
 * Dedupe findings (stable, first-wins with merging).
 * @param {Finding[]} findings
 * @returns {Finding[]}
 */
export function dedupeFindings(findings) {
  /** @type {Map<string, Finding>} */
  const byKey = new Map();
  /** @type {Finding[]} */
  const order = [];
  for (const finding of findings) {
    const key = dedupeKey(finding);
    const existing = byKey.get(key);
    if (existing) {
      mergeInto(existing, finding);
    } else {
      byKey.set(key, finding);
      order.push(finding);
    }
  }
  return order;
}

/** Pillar sort order (security first). */
/** @type {Record<Pillar, number>} */
const PILLAR_SORT = { security: 0, runtime: 1, architecture: 2, qa: 3 };

/**
 * Sort findings deterministically: pillar order → severity desc → file → line.
 * @param {Finding[]} findings
 * @returns {Finding[]} a new sorted array.
 */
export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const pillar = PILLAR_SORT[a.pillar] - PILLAR_SORT[b.pillar];
    if (pillar !== 0) return pillar;
    const severity = severityRank(b.severity) - severityRank(a.severity);
    if (severity !== 0) return severity;
    const file = a.file.localeCompare(b.file);
    if (file !== 0) return file;
    return (a.line ?? 0) - (b.line ?? 0);
  });
}
