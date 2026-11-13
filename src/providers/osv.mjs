// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview OSV-Scanner provider — local dependency CVE scan.
 *
 * Shells out to the `osv-scanner` binary (v2 CLI), which natively walks every
 * lockfile ecosystem (package-lock.json, requirements.txt, composer.lock,
 * go.sum, …). This is the only point in the engine that touches the network
 * (public OSV/ecosystem CVE lookups) — per the trust principles.
 *
 * osv-scanner v2 exits NON-ZERO when it finds vulnerabilities, so stdout is
 * captured regardless of exit status. Severity is derived from the scanner's
 * `groups[].max_severity` CVSS score (v2), with a fallback to the
 * `database_specific.severity` word on the detailed vulnerability entries.
 */
import { existsSync } from 'node:fs';
import { commandAvailable, runCommandCapture } from '../proc.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */

/** Map OSV database severity strings to our enum. */
const OSV_SEVERITY = /** @type {Record<string, Severity>} */ ({
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  MEDIUM: 'medium',
  LOW: 'low',
});

/** Ordinal severity rank, for keeping the highest. */
const SEVERITY_ORDER = /** @type {Record<Severity, number>} */ ({ critical: 4, high: 3, medium: 2, low: 1 });

/** @type {Provider} */
export const osvProvider = {
  id: 'osv',
  name: 'OSV-Scanner',
  available: () => commandAvailable('osv-scanner'),
  applicable: () => true,
  async run(_config, ctx) {
    const targets = ctx.targets.filter((target) => existsSync(target));
    if (targets.length === 0) {
      ctx.log('  no existing targets — nothing to scan');
      return [];
    }
    // `--allow-no-lockfiles` keeps a lockfile-less repo a 0-finding result
    // (not an error). osv-scanner exits non-zero when it FINDS vulns, so
    // capture stdout regardless of exit status.
    const { stdout } = runCommandCapture(
      'osv-scanner',
      ['scan', 'source', '--format', 'json', '--allow-no-lockfiles', '-r', ...targets],
      { cwd: ctx.repoRoot },
    );
    return parseOsvJson(stdout, ctx.repoRoot);
  },
};

/**
 * Parse `osv-scanner --format json` output into dependency findings.
 * @param {string} stdout
 * @param {string} repoRoot
 * @returns {Finding[]}
 */
export function parseOsvJson(stdout, repoRoot) {
  const parsed = JSON.parse(stdout);
  const results = /** @type {Array<Record<string, any>>} */ (Array.isArray(parsed.results) ? parsed.results : []);
  /** @type {Finding[]} */
  const findings = [];

  for (const result of results) {
    const absolutePath = String(result.source?.path ?? '');
    const file = absolutePath.startsWith(repoRoot)
      ? absolutePath.slice(repoRoot.length).replace(/^[/\\]+/, '')
      : absolutePath || 'lockfile';

    const packages = /** @type {Array<Record<string, any>>} */ (Array.isArray(result.packages) ? result.packages : []);
    for (const pkg of packages) {
      const name = String(pkg.package?.name ?? 'unknown');
      const version = pkg.package?.version != null ? String(pkg.package.version) : null;
      const ecosystem = pkg.package?.ecosystem != null ? String(pkg.package.ecosystem) : null;
      const groups = /** @type {Array<Record<string, any>>} */ (Array.isArray(pkg.groups) ? pkg.groups : []);
      const vulns = /** @type {Array<Record<string, any>>} */ (Array.isArray(pkg.vulnerabilities) ? pkg.vulnerabilities : []);
      if (groups.length === 0 && vulns.length === 0) continue;

      /** @type {string[]} */
      const cveIds = [];
      /** @type {string[]} */
      const titles = [];
      let severity = /** @type {Severity} */ ('medium');

      // Preferred: osv-scanner v2 `groups` — one entry per advisory, with the
      // numeric CVSS `max_severity`.
      for (const group of groups) {
        for (const id of /** @type {any[]} */ (Array.isArray(group.ids) ? group.ids : [])) {
          if (typeof id === 'string') cveIds.push(id);
        }
        for (const alias of /** @type {any[]} */ (Array.isArray(group.aliases) ? group.aliases : [])) {
          if (typeof alias === 'string') cveIds.push(alias);
        }
        if (typeof group.max_severity === 'string') {
          const score = Number.parseFloat(group.max_severity);
          if (!Number.isNaN(score)) severity = maxSeverity(severity, cvssToSeverity(score));
        }
      }

      // Fallback: detailed `vulnerabilities` entries (v1 / additional detail).
      for (const vuln of vulns) {
        const id = String(vuln.id ?? '');
        if (id) cveIds.push(id);
        for (const alias of /** @type {any[]} */ (Array.isArray(vuln.aliases) ? vuln.aliases : [])) {
          if (typeof alias === 'string') cveIds.push(alias);
        }
        const dbSeverity = vuln.database_specific?.severity;
        if (typeof dbSeverity === 'string') {
          const mapped = OSV_SEVERITY[dbSeverity.toUpperCase()];
          if (mapped) severity = maxSeverity(severity, mapped);
        }
        if (typeof vuln.summary === 'string') titles.push(vuln.summary);
      }

      const uniqueCves = [...new Set(cveIds)].sort();
      findings.push({
        id: `osv:${name}:${ecosystem ?? ''}`,
        kind: 'dependency',
        file,
        line: null,
        column: null,
        severity,
        pillar: 'security',
        teardownId: null,
        title: titles[0] ?? uniqueCves[0] ?? `Vulnerable dependency ${name}`,
        message: uniqueCves.length > 0 ? `${uniqueCves.length} known advisories` : null,
        fixSummary: version ? `Upgrade ${name} beyond ${version}` : `Upgrade ${name}`,
        source: { provider: 'osv', ruleId: uniqueCves[0] ?? null },
        dependency: { package: name, version, ecosystem, cveIds: uniqueCves },
      });
    }
  }

  return findings;
}

/**
 * Bucket a CVSS base score into the shared severity enum.
 * @param {number} score — 0.0–10.0.
 * @returns {Severity}
 */
function cvssToSeverity(score) {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Return the more severe of two severities.
 * @param {Severity} a
 * @param {Severity} b
 * @returns {Severity}
 */
function maxSeverity(a, b) {
  return SEVERITY_ORDER[b] > SEVERITY_ORDER[a] ? b : a;
}
