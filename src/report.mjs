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
  const testFindings = findings.filter((finding) => finding.inTests === true);
  const advisories = findings.filter((finding) => finding.advisory === true);
  const codeFindings = findings.filter(
    (finding) => finding.kind !== 'dependency' && !finding.inTests && !finding.advisory,
  );

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
  lines.push(...renderStack(report.stack));

  lines.push('## Findings Summary');
  lines.push('| Check | Findings | What |');
  lines.push('| --- | ---: | --- |');
  lines.push(...renderSummary(codeFindings, dependencies, testFindings, advisories));
  if (advisories.length > 0) {
    lines.push(`_${advisories.length} advisory finding(s) are reported below and are not scored._`);
  }
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

  if (testFindings.length > 0) {
    lines.push('');
    lines.push('## Findings in test files (not scored)');
    lines.push('_Test code is not shipped to production, so these do not affect the risk score — but a real secret committed to a test file is still public in git and worth fixing._');
    /** @type {string | null} */
    let currentPillar = null;
    for (const finding of testFindings) {
      if (finding.pillar !== currentPillar) {
        currentPillar = finding.pillar;
        lines.push('');
        lines.push(`### ${finding.pillar}`);
      }
      lines.push(formatFinding(finding));
    }
  }

  if (advisories.length > 0) {
    lines.push('');
    lines.push('## Advisories (not scored)');
    lines.push('_Informational — these do not affect the risk score. They are noted for awareness, not as defects._');
    /** @type {string | null} */
    let currentPillar = null;
    for (const finding of advisories) {
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
      [...codeFindings, ...testFindings]
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
 * Render the scan-time App Stack summary — a brief, readable sentence of what
 * the app is built on (framework, database, services). Detection is offline and
 * deterministic; the user is never asked.
 * @param {Record<string, boolean> | undefined} stack
 * @returns {string[]}
 */
function renderStack(stack) {
  if (!stack || Object.keys(stack).length === 0) return [];

  /** @type {string[]} */
  const parts = [];
  const firebaseBits = [];
  if (stack.firestore) firebaseBits.push('Firestore database');
  if (stack.cloudFunctions) firebaseBits.push('Cloud Functions');
  if (stack.storage) firebaseBits.push('Storage');
  if (stack.firebase || stack.firebaseAdmin || firebaseBits.length > 0) {
    parts.push(`Firebase (${firebaseBits.join(', ') || 'project'})`);
  }
  if (stack.prisma) parts.push('Prisma ORM');
  if (stack.express) parts.push('Express');

  // PHP backends (composer.json markers).
  if (stack.pimcore) parts.push('Pimcore (Symfony)');
  else if (stack.laravel) parts.push('Laravel');
  else if (stack.symfony) parts.push('Symfony');
  if (stack.doctrine) parts.push('Doctrine ORM');
  if (stack.twig) parts.push('Twig templates');

  const frontendBits = [];
  if (stack.next) frontendBits.push('Next.js');
  else if (stack.react) frontendBits.push('React');
  if (stack.vue) frontendBits.push('Vue');
  if (stack.vite) frontendBits.push('Vite');
  if (frontendBits.length > 0) parts.push(`${frontendBits.join(' + ')} frontend`);

  if (stack.stripe) parts.push('Stripe payments');

  if (parts.length === 0) return [];
  return ['## App Stack', `Detected: ${parts.join(' · ')}.`, ''];
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
 * @param {Finding[]} codeFindings — scored findings.
 * @param {import('./types.mjs').DependencySummary | undefined} dependencies
 * @param {Finding[]} testFindings — in-test findings, counted but not scored.
 * @param {Finding[]} advisories — reported but not scored.
 * @returns {string[]}
 */
function renderSummary(codeFindings, dependencies, testFindings, advisories) {
  /** @type {Map<string, Finding[]>} */
  const byProvider = new Map();
  for (const finding of codeFindings) {
    const provider = finding.source?.provider ?? 'unknown';
    const list = byProvider.get(provider);
    if (list) list.push(finding);
    else byProvider.set(provider, [finding]);
  }
  /** @type {Map<string, Finding[]>} */
  const advisoriesByProvider = new Map();
  for (const finding of advisories) {
    const provider = finding.source?.provider ?? 'unknown';
    const list = advisoriesByProvider.get(provider);
    if (list) list.push(finding);
    else advisoriesByProvider.set(provider, [finding]);
  }
  const order = ['semgrep', 'gitleaks', 'trivy', 'firebase', 'madge', 'deps', 'headers', 'ci', 'checkov', 'hadolint', 'bandit', 'gosec', 'phpstan', 'scc', 'eslint', 'tests', 'osv'];
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
    const scored = byProvider.get(provider) ?? [];
    const advisory = advisoriesByProvider.get(provider) ?? [];
    if (scored.length === 0 && advisory.length === 0) {
      lines.push(`| ${provider} | 0 | — |`);
      continue;
    }
    const counts = scored.length > 0 ? `${scored.length}` : '0';
    const findingsCell = advisory.length > 0 ? `${counts} · ${advisory.length} advisory` : counts;
    const what = [
      scored.length > 0 ? summarizeGroup(scored) : null,
      advisory.length > 0 ? `advisory: ${summarizeGroup(advisory)}` : null,
    ]
      .filter((part) => part !== null)
      .join(' · ');
    lines.push(`| ${provider} | ${findingsCell} | ${what} |`);
  }
  if (testFindings.length > 0) {
    lines.push(`| test files (not scored) | ${testFindings.length} | ${summarizeGroup(testFindings)} |`);
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
  const pkg = dep?.package ?? finding.file;
  const corroboration = finding.corroboratedBy?.length
    ? ` *(confirmed by ${finding.corroboratedBy.join(' + ')})*`
    : '';
  return `| ${finding.severity} | \`${pkg}\`${corroboration} | ${dep?.version ?? '?'} | ${cves || (finding.source.ruleId ?? 'CVE')} |${fix} |`;
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
  if (finding.corroboratedBy && finding.corroboratedBy.length > 0) {
    parts.push(`  - Confirmed by ${finding.corroboratedBy.join(' + ')} (cross-tool agreement).`);
  }
  if (finding.teardownId) {
    parts.push(`  → see ${teardownPath(finding.teardownId)}`);
  }
  return parts.join('\n');
}
