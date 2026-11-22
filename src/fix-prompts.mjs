// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview AI remediation prompts (FIX-PROMPTS.md).
 *
 * Turns a machine-readable `peek-report.json` into copy-paste prompts any AI
 * coding agent can act on — Claude Code, Cursor, Codex, aider, OpenCode with
 * DeepSeek, … — grounding each prompt in the finding's evidence (file:line,
 * message) and its teardown's fixSummary, never in generic advice. The
 * verification step is the closed loop the other scanners lack: re-run the
 * same scan and confirm the specific finding is gone.
 */
import { severityRank } from './scoring.mjs';

/** @typedef {import('./types.mjs').Finding} Finding */
/** @typedef {import('./types.mjs').Report} Report */

/** One remediation group: findings that share a fix. */
/**
 * @typedef {Object} RemediationGroup
 * @property {'teardown' | 'hygiene' | 'dependency'} kind
 * @property {string} title — group heading.
 * @property {string | null} teardownId — TD id (teardown groups only).
 * @property {string | null} ruleId — hygiene rule id (hygiene groups only).
 * @property {string | null} message — shared explanation (first non-empty).
 * @property {string | null} fixSummary — shared fix.
 * @property {Array<{ file: string; line: number | null; note: string }>} locations
 * @property {Array<{ package: string; ecosystem: string | null; cveIds: string[] }>} packages
 * @property {'critical' | 'high' | 'medium' | 'low'} severity — the group's highest severity.
 * @property {boolean} advisory — every member is advisory (policy signal, not scored).
 */

/**
 * Group actionable findings into remediation groups.
 *
 * - Teardown findings group by `(teardownId, title)` — one fix per defect class.
 * - Hygiene findings group by `(ruleId, title)`.
 * - Dependency CVEs collapse into ONE group — "upgrade these packages" is a
 *   single remediation, listing every affected package.
 *
 * Groups are ordered by highest severity first (teardown groups beat equal
 * hygiene groups — curated fixes outrank linter noise).
 * @param {Finding[]} findings
 * @returns {RemediationGroup[]}
 */
export function groupRemediationFindings(findings) {
  /** @type {Map<string, RemediationGroup>} */
  const byKey = new Map();

  for (const finding of findings) {
    const key = remediationKey(finding);
    let group = byKey.get(key);
    if (!group) {
      group = emptyGroup(finding, key);
      byKey.set(key, group);
    }
    if (finding.severity && severityRank(finding.severity) > severityRank(group.severity)) {
      group.severity = finding.severity;
    }
    if (group.advisory && !finding.advisory) group.advisory = false;
    if (finding.kind === 'dependency' && finding.dependency) {
      group.packages.push({
        package: finding.dependency.package,
        ecosystem: finding.dependency.ecosystem,
        cveIds: finding.dependency.cveIds,
      });
      continue;
    }
    group.locations.push({
      file: finding.file,
      line: finding.line,
      note: finding.inTests
        ? 'in a test/fixture file — reported, not scored'
        : finding.advisory
          ? 'advisory — reported, not scored'
          : '',
    });
  }

  return [...byKey.values()].sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    // Curated teardown fixes outrank linter noise at equal severity.
    /** @param {RemediationGroup} g */
    const curated = (g) => (g.kind === 'teardown' ? 0 : g.kind === 'dependency' ? 2 : 1);
    return curated(a) - curated(b);
  });
}

/**
 * A stable, dedup-safe key for one remediation group.
 * @param {Finding} finding
 * @returns {string}
 */
function remediationKey(finding) {
  if (finding.kind === 'dependency') return 'dep:all';
  if (finding.kind === 'teardown') {
    return `td:${finding.teardownId ?? '?'}:${finding.title}`;
  }
  return `hy:${finding.source?.ruleId ?? '?'}:${finding.title}`;
}

/**
 * Create the initial group for a finding.
 * @param {Finding} finding
 * @param {string} key
 * @returns {RemediationGroup}
 */
function emptyGroup(finding, key) {
  const isDependency = finding.kind === 'dependency';
  return {
    kind: finding.kind,
    // One group holds EVERY dependency CVE — title it by the remediation, not
    // by whichever CVE happened to sort first.
    title: isDependency ? 'Upgrade dependencies with known CVEs' : finding.title,
    teardownId: finding.kind === 'teardown' ? finding.teardownId : null,
    ruleId: finding.kind === 'hygiene' ? (finding.source?.ruleId ?? key) : null,
    message: isDependency ? null : finding.message,
    fixSummary: isDependency ? null : finding.fixSummary,
    locations: [],
    packages: [],
    severity: finding.severity,
    advisory: finding.advisory === true,
  };
}

/**
 * Render `FIX-PROMPTS.md` from a report.
 * @param {Report} report
 * @returns {{ markdown: string; count: number }}
 */
export function renderFixPrompts(report) {
  const groups = groupRemediationFindings(report.findings ?? []);
  const lines = [];

  lines.push(`# Fix Prompts — ${report.engine?.name ?? 'vibe-check'} remediation guide`);
  lines.push('');
  lines.push(
    `Generated from \`peek-report.json\` (${new Date(report.generatedAt ?? Date.now()).toISOString().slice(0, 10)}).`,
  );
  lines.push(
    'Copy ONE section at a time into any AI coding agent that can edit files —',
    'Claude Code, Cursor, Codex, aider, OpenCode (incl. DeepSeek) — or use the',
    'bundled Claude Code skill (`skills/vibe-check/`). Fix, verify, move on.',
  );
  lines.push('');

  if (groups.length === 0) {
    lines.push('No actionable findings — nothing to fix.');
    return { markdown: lines.join('\n') + '\n', count: 0 };
  }

  lines.push(`## Checklist (${groups.length} fixes)`);
  lines.push('');
  groups.forEach((group, index) => {
    const sev = group.severity.toUpperCase();
    lines.push(`- [ ] ${index + 1}. ${groupHeading(group)} — ${sev}`);
  });
  lines.push('');
  lines.push('---');
  lines.push('');

  groups.forEach((group, index) => {
    lines.push(`## Fix ${index + 1} — ${groupHeading(group)}`);
    lines.push('');

    const locations = group.kind === 'dependency' ? group.packages : group.locations;
    const bullet = locations
      .map((location) => {
        if (group.kind === 'dependency') {
          const pkg = /** @type {{ package: string; ecosystem: string | null; cveIds: string[] }} */ (location);
          const cves = pkg.cveIds.length > 0 ? ` (${pkg.cveIds.join(', ')})` : '';
          return `- \`${pkg.package}\`${pkg.ecosystem ? ` [${pkg.ecosystem}]` : ''}${cves}`;
        }
        const loc = /** @type {{ file: string; line: number | null; note: string }} */ (location);
        const note = loc.note ? ` — ${loc.note}` : '';
        return `- \`${loc.file}${loc.line ? `:${loc.line}` : ''}\`${note}`;
      })
      .join('\n');

    if (group.kind === 'dependency') {
      lines.push('**Affected packages:**');
      lines.push(bullet);
      lines.push('');
      lines.push(
        '**Fix:** Upgrade every package above to a version that resolves the listed',
        'CVEs — prefer the latest patched release in the same major range, then',
        're-run the dependency lockfile install. Never pin to a version the',
        'advisory says is still affected.',
      );
    } else {
      lines.push('**Locations:**');
      lines.push(bullet);
      lines.push('');
      if (group.message) {
        lines.push('**What\'s wrong:**');
        lines.push(group.message);
        lines.push('');
      }
      if (group.fixSummary) {
        lines.push('**Fix:**');
        lines.push(group.fixSummary);
        lines.push('');
      }
      if (group.teardownId) {
        lines.push(`**Deep dive:** https://peek.software/teardowns/${group.teardownId}`);
        lines.push('');
      }
    }

    lines.push('**Scope:**');
    lines.push(
      '- Fix every location listed above.',
      '- Then search this codebase for the same pattern and fix those occurrences too.',
      '- Do not change unrelated behavior, and keep the public API/UX identical.',
    );
    lines.push('');
    lines.push('**Verify:**');
    lines.push(
      '- Re-run the same `vibe-check run --config <your-config>` that produced this report.',
      '- Confirm none of the locations above is reported again.',
      '- Run the project\'s own test suite.',
    );
    lines.push('');
    lines.push('---');
    lines.push('');
  });

  lines.push('');
  lines.push(
    'When every box above is ticked, record the result in the team\'s run log',
    '(e.g. `docs/BUILD_RUN_<date>.md`) as `- [x] <finding id> — fixed in <file>`,',
    'or `- [ ] <finding id> — false positive, <why>` when you intentionally left it.',
    'A later scan can then cross-check each claim against the code.',
  );

  return { markdown: lines.join('\n') + '\n', count: groups.length };
}

/**
 * A compact heading for a group: `TD-033: String-concatenated SQL`.
 * @param {RemediationGroup} group
 * @returns {string}
 */
function groupHeading(group) {
  const id = group.teardownId ?? group.ruleId;
  return id ? `${id}: ${group.title}` : group.title;
}
