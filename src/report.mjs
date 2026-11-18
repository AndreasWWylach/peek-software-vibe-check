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

/** Emoji per pillar (for the section headings). */
const PILLAR_EMOJI = /** @type {Record<string, string>} */ ({
  security: '🔒',
  runtime: '⚙️',
  architecture: '🏗️',
  qa: '🧪',
});

/** Emoji per severity (scored findings) — the at-a-glance severity cue. */
const SEVERITY_BADGE = /** @type {Record<string, string>} */ ({
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
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
  const { engine, generatedAt, riskScore, pillars, findings, skippedProviders, disabledChecks, notStaticallyVerifiable, dependencies } = report;
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
  if (report.readiness) {
    lines.push(...renderReadiness(report.readiness));
  }
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

  if (report.agentProvenance) {
    lines.push(...renderAgentProvenance(report.agentProvenance));
  }

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
    renderFindingBlocks(lines, codeFindings);
  }

  if (testFindings.length > 0) {
    lines.push('');
    lines.push('## Findings in test files (not scored)');
    lines.push('_Test code is not shipped to production, so these do not affect the risk score — but a real secret committed to a test file is still public in git and worth fixing._');
    renderFindingBlocks(lines, testFindings);
  }

  if (advisories.length > 0) {
    lines.push('');
    lines.push('## Advisories (not scored)');
    lines.push('_Informational — these do not affect the risk score. They are noted for awareness, not as defects._');
    renderFindingBlocks(lines, advisories);
  }

  if (skippedProviders.length > 0) {
    lines.push('');
    lines.push('## Skipped Checks');
    for (const skipped of skippedProviders) {
      lines.push(`- **${skipped.id}** (${skipped.reason}): ${skipped.detail ?? ''}`);
    }
  }

  if ((disabledChecks ?? []).length > 0) {
    lines.push('');
    lines.push('## Disabled Checks');
    lines.push('_These checks were not scored — the risk score above does not cover them._');
    for (const check of disabledChecks) {
      lines.push(`- **${check.id}** — ${check.detail}`);
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
  if (stack.sql) parts.push('SQL migrations');
  if (stack.express) parts.push('Express');

  // PHP backends (composer.json markers). Pimcore is Symfony-based and always
  // renders via Twig — its package.json `react` dep is the admin UI build
  // tooling, not the app's own frontend, so it must not claim a React frontend.
  if (stack.pimcore) {
    parts.push('Pimcore (Symfony)');
    parts.push('Twig templates');
  } else if (stack.laravel) {
    parts.push('Laravel');
    if (stack.twig) parts.push('Twig templates');
  } else if (stack.symfony) {
    parts.push('Symfony');
    if (stack.twig) parts.push('Twig templates');
  }
  if (stack.doctrine) parts.push('Doctrine ORM');

  // A JS "frontend" is only meaningful for JS-first apps; inside a Pimcore app
  // the JS deps are admin tooling, so we skip the label there.
  const frontendBits = [];
  if (!stack.pimcore) {
    if (stack.next) frontendBits.push('Next.js');
    else if (stack.react) frontendBits.push('React');
    if (stack.vue) frontendBits.push('Vue');
    if (stack.vite) frontendBits.push('Vite');
  }
  if (frontendBits.length > 0) parts.push(`${frontendBits.join(' + ')} frontend`);

  if (stack.stripe) parts.push('Stripe payments');

  if (parts.length === 0) return [];
  return ['## App Stack', `Detected: ${parts.join(' · ')}.`, ''];
}

/**
 * Render the agent-provenance note — official AI-coding tool markers plus any
 * user-named agent-workflow log files. Report-level context, never scored.
 * @param {import('./types.mjs').AgentProvenance} provenance
 * @returns {string[]}
 */
function renderAgentProvenance(provenance) {
  /** @type {string[]} */
  const lines = ['## Agent Provenance'];
  if (provenance.signals.length > 0) {
    lines.push('Official AI-coding tool markers detected:');
    for (const signal of provenance.signals) lines.push(`- ${signal}`);
  } else {
    lines.push('_No official AI-coding tool markers detected._');
  }
  if (provenance.agentLogFiles.length > 0) {
    lines.push('Agent-workflow log files you asked to watch:');
    for (const file of provenance.agentLogFiles) lines.push(`- \`${file}\``);
  }
  lines.push('');
  return lines;
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
 * Render the go-live readiness verdict (go / conditional / no-go) with its
 * concrete launch conditions. Leads the report because it answers the question
 * the headline score does not: "can I ship this?".
 * @param {import('./types.mjs').Readiness} readiness
 * @returns {string[]}
 */
function renderReadiness(readiness) {
  /** @type {string[]} */
  const lines = ['## Go-Live Readiness'];
  const emoji = readiness.status === 'go' ? '🟢' : readiness.status === 'conditional' ? '🟡' : '🔴';
  const label = readiness.status === 'go' ? 'Ready to go live' : readiness.status === 'conditional' ? 'Ready with conditions' : 'Do not go live';
  lines.push(`**${emoji} ${label}**`);
  for (const condition of readiness.conditions) {
    lines.push(`- ${condition}`);
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
  const byProvider = bucketByProvider(codeFindings);
  const advisoriesByProvider = bucketByProvider(advisories);
  const testsByProvider = bucketByProvider(testFindings);
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
    const tests = testsByProvider.get(provider) ?? [];
    if (scored.length === 0 && advisory.length === 0 && tests.length === 0) {
      lines.push(`| ${provider} | 0 | — |`);
      continue;
    }
    const counts = scored.length > 0 ? `${scored.length}` : '0';
    const qualifiers = [];
    if (advisory.length > 0) qualifiers.push(`${advisory.length} advisory`);
    if (tests.length > 0) qualifiers.push(`${tests.length} in tests`);
    const findingsCell = qualifiers.length > 0 ? `${counts} · ${qualifiers.join(' · ')}` : counts;
    const what = [
      scored.length > 0 ? summarizeGroup(scored) : null,
      advisory.length > 0 ? `advisory: ${summarizeGroup(advisory)}` : null,
      tests.length > 0 ? `test files: ${summarizeGroup(tests)}` : null,
    ]
      .filter((part) => part !== null)
      .join(' · ');
    lines.push(`| ${provider} | ${findingsCell} | ${what} |`);
  }
  return lines;
}

/**
 * Bucket findings by their source provider id.
 * @param {Finding[]} findings
 * @returns {Map<string, Finding[]>}
 */
function bucketByProvider(findings) {
  /** @type {Map<string, Finding[]>} */
  const byProvider = new Map();
  for (const finding of findings) {
    const provider = finding.source?.provider ?? 'unknown';
    const list = byProvider.get(provider);
    if (list) list.push(finding);
    else byProvider.set(provider, [finding]);
  }
  return byProvider;
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
    if (moment.teardownIds.length === 0) {
      lines.push(`- ℹ️ ${moment.questionId}: no static rule covers this question.`);
      continue;
    }
    for (const teardownId of moment.teardownIds) {
      if (moment.found.includes(teardownId)) {
        lines.push(`- ⚠️ ${moment.questionId} → ${teardownId}: you reported this handled, but the scan found it.`);
      } else {
        lines.push(`- ✅ ${moment.questionId} → ${teardownId}: not found by the scan.`);
      }
    }
  }
  lines.push('');
  return lines;
}

/**
 * A pillar section heading with its human label + a fixed emoji, so the report
 * reads as a guided tour rather than a flat list of lowercase keys.
 * @param {import('./types.mjs').Pillar} pillar
 * @returns {string}
 */
function pillarHeading(pillar) {
  const emoji = PILLAR_EMOJI[pillar] ?? '';
  const label = PILLAR_LABELS[pillar] ?? pillar;
  return `### ${emoji} ${label}`;
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

  // Scored findings carry a severity badge; advisories a neutral lightbulb —
  // so "errors" and "informational" never look the same at a glance.
  const marker = finding.advisory ? '💡' : SEVERITY_BADGE[finding.severity] ?? 'ℹ️';
  const head = finding.teardownId ?? finding.source.ruleId ?? finding.id;
  const parts = [`- ${marker} **${head}** · \`${location}\` — ${finding.title}`];
  if (finding.message && finding.message !== finding.title) {
    parts.push(`  - ${finding.message}`);
  }
  if (finding.fixSummary) {
    parts.push(`  - 🔧 Fix: ${finding.fixSummary}`);
  }
  if (finding.corroboratedBy && finding.corroboratedBy.length > 0) {
    parts.push(`  - 🤝 Confirmed by ${finding.corroboratedBy.join(' + ')} (cross-tool agreement).`);
  }
  if (finding.teardownId) {
    parts.push(`  → ${teardownPath(finding.teardownId)}`);
  }
  return parts.join('\n');
}

/**
 * Render grouped findings as pillar blocks: `### <emoji> <label>` headings,
 * then the grouped entries. Findings / test-files / advisories all share this
 * layout, so it lives here once.
 * @param {string[]} lines — output sink.
 * @param {Finding[]} findings
 */
function renderFindingBlocks(lines, findings) {
  /** @type {string | null} */
  let currentPillar = null;
  for (const group of groupFindings(findings)) {
    if (group.pillar !== currentPillar) {
      currentPillar = group.pillar;
      lines.push('');
      lines.push(pillarHeading(group.pillar));
    }
    lines.push(formatFindingGroup(group.key, group.findings));
    lines.push('');
  }
}

/**
 * Group findings by (pillar, key) — teardown id, else rule id, else id —
 * preserving first-seen order, so one issue renders once with its sites listed.
 * @param {Finding[]} findings
 * @returns {Array<{ pillar: import('./types.mjs').Pillar; key: string; findings: Finding[] }>}
 */
function groupFindings(findings) {
  /** @type {Map<string, { pillar: import('./types.mjs').Pillar; key: string; findings: Finding[] }>} */
  const groups = new Map();
  for (const finding of findings) {
    const pillar = finding.pillar;
    const key = finding.teardownId ?? finding.source?.ruleId ?? finding.id;
    // Group only when the explanation is identical too — findings sharing an id
    // but with different messages (e.g. checkov per-resource detail) stay as
    // their own entries rather than collapsing the detail away.
    const mapKey = `${pillar}\u0000${key}\u0000${finding.title}\u0000${finding.message ?? ''}`;
    const group = groups.get(mapKey);
    if (group) group.findings.push(finding);
    else groups.set(mapKey, { pillar, key, findings: [finding] });
  }
  return [...groups.values()];
}

/**
 * Format a group of findings sharing one key. A single-site finding stays an
 * inline bullet; a multi-site one becomes a header with the shared explanation
 * once, then a compact list of the files it touched.
 * @param {string} key
 * @param {Finding[]} findings
 * @returns {string}
 */
function formatFindingGroup(key, findings) {
  const first = findings[0];
  if (findings.length === 1) return formatFinding(first);

  const marker = first.advisory ? '💡' : SEVERITY_BADGE[first.severity] ?? 'ℹ️';
  /** @type {(finding: Finding) => string} */
  const location = (finding) =>
    finding.line != null ? `${finding.file}:${finding.line}` : finding.file;

  const lines = [`- ${marker} **${key}** — ${first.title} (${findings.length})`];
  if (first.message && first.message !== first.title) lines.push(`  - ${first.message}`);
  if (first.fixSummary) lines.push(`  - 🔧 Fix: ${first.fixSummary}`);
  if (first.corroboratedBy?.length) {
    lines.push(`  - 🤝 Confirmed by ${first.corroboratedBy.join(' + ')} (cross-tool agreement).`);
  }
  if (first.teardownId) lines.push(`  → ${teardownPath(first.teardownId)}`);
  for (const finding of findings) lines.push(`  - \`${location(finding)}\``);
  return lines.join('\n');
}
