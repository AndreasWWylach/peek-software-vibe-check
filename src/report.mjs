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
 * Render the human-readable Markdown report (`AUDIT-REPORT.md`).
 * @param {Report} report
 * @returns {string}
 */
export function renderMarkdown(report) {
  const { engine, generatedAt, riskScore, pillars, findings, skippedProviders, notStaticallyVerifiable } = report;
  /** @type {string[]} */
  const lines = [];

  lines.push('# Local Deep Code Audit Report');
  lines.push(`**Date:** ${generatedAt.slice(0, 10)}`);
  lines.push(`**Engine:** ${engine.name} ${engine.version} (public, commit ${engine.commit ?? 'n/a'})`);
  lines.push('');
  lines.push('## Overall Risk Score');
  lines.push(`- ${riskScore.total} / ${riskScore.max} — ${TIER_EMOJI[riskScore.tier]} ${TIER_LABEL[riskScore.tier]}`);
  lines.push('');
  lines.push('## Pillar Breakdown');
  lines.push('| Pillar | Risk Score | Max |');
  lines.push('| --- | ---: | ---: |');
  for (const pillar of pillars) {
    lines.push(`| ${pillar.label} | ${pillar.score} | ${pillar.max} |`);
  }
  lines.push('');
  if (report.calibration) {
    lines.push(...renderCalibration(report.calibration));
  }
  lines.push('## Findings');

  if (findings.length === 0) {
    lines.push('_No findings._');
  } else {
    /** @type {string | null} */
    let currentPillar = null;
    for (const finding of findings) {
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
  lines.push('- Get It Fixed by Last Mile');
  lines.push('');
  return lines.join('\n');
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
