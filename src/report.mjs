// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Report renderer — Markdown (human) + JSON (machine) for the audit.
 */
import { getRiskTier, MAX_TOTAL_SCORE, PILLAR_LABELS, SEVERITY_RANK } from './scoring.mjs';

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
  lines.push(...renderVerdict(riskScore, codeFindings, dependencies, dependencyFindings));
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
 * The one-glance, plain-language verdict at the top of the report: the code
 * score in words, the single most common code issue, and the worst dependency.
 * @param {{ total: number; max: number; tier: import('./types.mjs').Tier }} riskScore
 * @param {Finding[]} codeFindings
 * @param {import('./types.mjs').DependencySummary | undefined} dependencies
 * @param {Finding[]} dependencyFindings
 * @returns {string[]}
 */
function renderVerdict(riskScore, codeFindings, dependencies, dependencyFindings) {
  /** @type {string[]} */
  const lines = ['## Verdict'];

  const top = topCodeIssue(codeFindings);
  lines.push(
    `Your code scores **${riskScore.total}/${riskScore.max}** — ${TIER_LABEL[riskScore.tier]}` +
      (top ? `; the top issue is **${top.title}** (${top.count} ${top.severity}).` : '.'),
  );

  if (dependencies && dependencies.total > 0) {
    const worst = [...dependencyFindings].sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
    )[0];
    lines.push(
      `Your dependencies carry **${dependencies.total} known CVE(s)**` +
        (worst
          ? `; the worst is ${worst.severity} \`${worst.dependency?.package ?? worst.file}\` — upgrade to fix.`
          : '.'),
    );
  }

  lines.push('');
  return lines;
}

/**
 * The single most noteworthy code issue: Peek teardown findings outrank generic
 * linter hygiene, then severity, then count.
 * @param {Finding[]} codeFindings
 * @returns {{ title: string; count: number; severity: import('./types.mjs').Severity } | null}
 */
function topCodeIssue(codeFindings) {
  /** @type {Map<string, { title: string; count: number; severity: import('./types.mjs').Severity; teardownId?: string }>} */
  const groups = new Map();
  for (const finding of codeFindings) {
    const key = finding.teardownId ?? finding.source?.ruleId ?? finding.title;
    const group = groups.get(key);
    if (group) {
      group.count += 1;
      if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[group.severity]) group.severity = finding.severity;
    } else {
      groups.set(key, {
        title: finding.title,
        count: 1,
        severity: finding.severity,
        teardownId: finding.teardownId ?? undefined,
      });
    }
  }
  if (groups.size === 0) return null;
  return [...groups.values()].sort((a, b) => {
    // Curated teardown issues (the "I didn't know that" ones) beat linter noise.
    if (Boolean(a.teardownId) !== Boolean(b.teardownId)) return a.teardownId ? -1 : 1;
    return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count;
  })[0];
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
  const order = ['semgrep', 'gitleaks', 'madge', 'scc', 'eslint', 'osv'];
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
  const ids = dep?.cveIds ?? [];
  // Long CVE lists (e.g. undici) would blow up the table cell — truncate.
  const cves = ids.length > 3
    ? `${ids.slice(0, 3).join(', ')} … +${ids.length - 3} more`
    : ids.join(', ');
  const fix = finding.fixSummary ? ` ${finding.fixSummary}` : '';
  return `| ${finding.severity} | \`${dep?.package ?? finding.file}\` | ${dep?.version ?? '?'} | ${cves || (finding.source.ruleId ?? 'CVE')} |${fix} |`;
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
  const parts = [`- **${head}** (\`${location}\`): ${finding.title}`];
  // Explain the finding, then how to fix it — the "one glance → oh, that's
  // why" moment the report is aiming for.
  if (finding.message && finding.message !== finding.title) {
    parts.push(`  - ${finding.message}`);
  }
  if (finding.fixSummary) {
    parts.push(`  - Fix: ${finding.fixSummary}`);
  }
  if (finding.teardownId) {
    parts.push(`  → see ${teardownPath(finding.teardownId)}`);
  }
  return parts.join('\n');
}
