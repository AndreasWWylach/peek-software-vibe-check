// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Report renderer — Markdown (human) + JSON (machine) for the audit.
 */
import { getRiskTier, MAX_TOTAL_SCORE, PILLAR_LABELS } from './scoring.mjs';

/** @typedef {import('./types.mjs').Report} Report */
/** @typedef {import('./types.mjs').Finding} Finding */
/** @typedef {import('./types.mjs').Tier} Tier */
/** @typedef {import('./types.mjs').Calibration} Calibration */

/** Emoji per risk tier (for the Markdown report). */
const TIER_EMOJI = /** @type {Record<Tier, string>} */ ({ green: '🟢', amber: '🟡', red: '🔴' });

/** Human label per risk tier (for the Markdown report). */
const TIER_LABEL = /** @type {Record<Tier, string>} */ ({
  green: 'Looks Solid',
  amber: 'Needs Hardening',
  red: 'High Risk',
});

/**
 * Deep-link to a teardown's editorial page on peek.software.
 * @param {string} teardownId — e.g. "TD-008".
 * @returns {string} the public URL.
 */
export function teardownPath(teardownId) {
  return `https://peek.software/teardowns/${teardownId}`;
}

/**
 * Deep-link to the LastMile hand-off (finding IDs only — never code).
 * @param {string[]} teardownIds — e.g. ["TD-008", "TD-016"].
 * @returns {string} the public fix URL (peek.software redirects to Last Mile).
 */
export function fixPath(teardownIds) {
  return `https://peek.software/fix?findings=${teardownIds.join(',')}`;
}

/**
 * Render the human-readable Markdown report (`AUDIT-REPORT.md`).
 * @param {Report} report
 * @returns {string}
 */
export function renderMarkdown(report) {
  const { engine, generatedAt, riskScore, pillars, findings, skippedProviders, notStaticallyVerifiable, dependencies } = report;
  const dependencyFindings = findings.filter((finding) => finding.kind === 'dependency');
  const codeFindings = findings.filter((finding) => finding.kind !== 'dependency');

  /** @type {string[]} */
  const lines = [];

  lines.push('# Local Deep Code Audit Report');
  lines.push(`**Date:** ${generatedAt.slice(0, 10)}`);
  lines.push(`**Engine:** ${engine.name} ${engine.version} (public, commit ${engine.commit ?? 'n/a'})`);
  lines.push('');
  lines.push('## Overall Risk');
  lines.push(`- **Your code:** ${riskScore.total} / ${riskScore.max} — ${TIER_EMOJI[riskScore.tier]} ${TIER_LABEL[riskScore.tier]}`);
  if (dependencies && dependencies.total > 0) {
    lines.push(
      `- **Dependencies:** ${dependencies.total} known CVE(s) — ${severitySpread(dependencies)} (reported separately below)`,
    );
  } else {
    lines.push('- **Dependencies:** none found.');
  }
  lines.push('');

  lines.push('## Findings Summary');
  lines.push('| Check | Findings | What |');
  lines.push('| --- | ---: | --- |');
  lines.push(...renderSummary(codeFindings, dependencies));
  lines.push('');

  lines.push('## Pillar Breakdown');
  lines.push('| Pillar | Risk Score | Max |');
  lines.push('| --- | ---: | ---: |');
  for (const pillar of pillars) {
    lines.push(`| ${pillar.label} | ${pillar.score} | ${pillar.max} |`);
  }
  lines.push('');
  lines.push('_How this is scored: each finding adds points by severity — critical 20, high 10, medium 5, low 2 — to its pillar (capped at the pillar max). Dependency CVEs are not part of this score; they are reported separately below._');
  lines.push('');

  if (report.calibration) {
    lines.push(...renderCalibration(report.calibration));
  }

  if (dependencyFindings.length > 0) {
    lines.push('## External Dependencies (CVEs)');
    lines.push('| Severity | Package | Version | CVEs | Fix |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const finding of dependencyFindings) {
      lines.push(formatDependency(finding));
    }
    lines.push('');
  }

  lines.push('## Findings (your code)');

  if (codeFindings.length === 0) {
    lines.push('_No findings._');
  } else {
    /** @type {string | null} */
    let currentPillar = null;
    for (const finding of codeFindings) {
      if (finding.pillar !== currentPillar) {
        currentPillar = finding.pillar;
        lines.push('');
        lines.push(`### ${finding.pillar}`);
      }
      lines.push(formatFinding(finding));
    }
  }

  if (skippedProviders.length > 0) {
    lines.push('');
    lines.push('## Skipped Checks');
    for (const skipped of skippedProviders) {
      lines.push(`- **${skipped.id}** (${skipped.reason}): ${skipped.detail ?? ''}`);
    }
  }

  if (notStaticallyVerifiable.length > 0) {
    lines.push('');
    lines.push('## Not Statically Verifiable');
    for (const item of notStaticallyVerifiable) {
      lines.push(`- ${item.teardownId} — ${item.title} — ${item.guidance}`);
    }
  }

  lines.push('');
  lines.push('## Next Steps');
  const teardownIds = [
    ...new Set(
      codeFindings
        .map((finding) => finding.teardownId)
        .filter((id) => typeof id === 'string')
        .map((id) => /** @type {string} */ (id)),
    ),
  ];
  if (teardownIds.length > 0) {
    lines.push(`- Get It Fixed by Last Mile → ${fixPath(teardownIds)}`);
  } else {
    lines.push('- Get It Fixed by Last Mile');
  }
  lines.push('');
  return lines.join('\n');
}

/**
 * Render the per-provider "Findings Summary" table rows.
 * @param {Finding[]} codeFindings
 * @param {import('./types.mjs').DependencySummary | undefined} dependencies
 * @returns {string[]}
 */
function renderSummary(codeFindings, dependencies) {
  /** @type {Map<string, Finding[]>} */
  const byProvider = new Map();
  for (const finding of codeFindings) {
    const provider = finding.source?.provider ?? 'unknown';
    const list = byProvider.get(provider);
    if (list) list.push(finding);
    else byProvider.set(provider, [finding]);
  }

  const order = ['semgrep', 'osv', 'madge', 'scc', 'gitleaks', 'eslint'];
  /** @type {string[]} */
  const lines = [];
  for (const provider of order) {
    if (provider === 'osv') {
      if (dependencies && dependencies.total > 0) {
        lines.push(`| OSV-Scanner | ${dependencies.total} CVE(s) | ${severitySpread(dependencies)} — see External Dependencies |`);
      } else {
        lines.push('| OSV-Scanner | 0 | — |');
      }
      continue;
    }
    const list = byProvider.get(provider) ?? [];
    if (list.length === 0) {
      lines.push(`| ${provider} | 0 | — |`);
      continue;
    }
    lines.push(`| ${provider} | ${list.length} | ${summarizeGroup(list)} |`);
  }
  return lines;
}

/**
 * Compact "teardown ×count, …" description of a provider's findings.
 * @param {Finding[]} findings
 * @returns {string}
 */
function summarizeGroup(findings) {
  /** @type {Map<string, number>} */
  const byKey = new Map();
  for (const finding of findings) {
    const key = finding.teardownId ?? finding.source.ruleId ?? '?';
    byKey.set(key, (byKey.get(key) ?? 0) + 1);
  }
  return [...byKey.entries()].map(([key, count]) => `${key} ×${count}`).join(', ');
}

/**
 * A "5 critical, 7 high" severity rollup string.
 * @param {{ critical: number; high: number; medium: number; low: number }} summary
 * @returns {string}
 */
function severitySpread(summary) {
  const parts = [];
  if (summary.critical) parts.push(`${summary.critical} critical`);
  if (summary.high) parts.push(`${summary.high} high`);
  if (summary.medium) parts.push(`${summary.medium} medium`);
  if (summary.low) parts.push(`${summary.low} low`);
  return parts.length > 0 ? parts.join(', ') : '—';
}

/**
 * Format a dependency (CVE) finding as a Markdown table row.
 * @param {Finding} finding
 * @returns {string}
 */
function formatDependency(finding) {
  const dep = finding.dependency;
  const cves = dep?.cveIds?.join(', ') ?? finding.source.ruleId ?? 'CVE';
  const fix = finding.fixSummary ? ` ${finding.fixSummary}` : '';
  return `| ${finding.severity} | \`${dep?.package ?? finding.file}\` | ${dep?.version ?? '?'} | ${cves} |${fix} |`;
}

/**
 * Render the self-report vs. scan calibration overlay (docs §3 level 2).
 * @param {Calibration} calibration
 * @returns {string[]}
 */
function renderCalibration(calibration) {
  /** @type {string[]} */
  const lines = [];
  const selfTier = getRiskTier(Math.round((calibration.selfReport / MAX_TOTAL_SCORE) * 100));
  const scanTier = getRiskTier(Math.round((calibration.scan / MAX_TOTAL_SCORE) * 100));

  lines.push('## Self-Report vs. Scan');
  lines.push(`- Self-reported: ${calibration.selfReport} / ${MAX_TOTAL_SCORE} — ${TIER_EMOJI[selfTier]} ${TIER_LABEL[selfTier]}`);
  lines.push(`- Scan: ${calibration.scan} / ${MAX_TOTAL_SCORE} — ${TIER_EMOJI[scanTier]} ${TIER_LABEL[scanTier]}`);
  lines.push('');
  lines.push('| Pillar | Self-report | Scan |');
  lines.push('| --- | ---: | ---: |');
  for (const pillar of calibration.pillars) {
    lines.push(`| ${PILLAR_LABELS[pillar.pillar]} | ${pillar.selfReport} | ${pillar.scan} |`);
  }
  lines.push('');
  lines.push('## Calibration');
  for (const moment of calibration.moments) {
    if (moment.found) {
      lines.push(`- ⚠️ ${moment.questionId} → ${moment.teardownId}: you reported this handled, but the scan found it.`);
    } else if (moment.teardownId) {
      lines.push(`- ✅ ${moment.questionId} → ${moment.teardownId}: not found by the scan.`);
    } else {
      lines.push(`- ℹ️ ${moment.questionId}: no static rule covers this question.`);
    }
  }
  lines.push('');
  return lines;
}

/**
 * Format a single finding as a Markdown bullet.
 * @param {Finding} finding
 * @returns {string}
 */
function formatFinding(finding) {
  const location = finding.line != null ? `${finding.file}:${finding.line}` : finding.file;

  if (finding.kind === 'dependency' && finding.dependency) {
    const cves = finding.dependency.cveIds.join(', ');
    const head = cves || finding.title;
    const fix = finding.fixSummary ? ` — fix: ${finding.fixSummary}` : '';
    return `- **${head}** \`${finding.dependency.package}@${finding.dependency.version ?? '?'}\` (\`${location}\`): ${finding.title}${fix}`;
  }

  const head = finding.teardownId ?? finding.source.ruleId ?? finding.id;
  const deepLink = finding.teardownId ? `\n  → see ${teardownPath(finding.teardownId)}` : '';
  return `- **${head}** (\`${location}\`): ${finding.title}${deepLink}`;
}
