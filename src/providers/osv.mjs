// @ts-check
/**
 * @fileoverview OSV-Scanner provider — local dependency CVE scan.
 *
 * Shells out to the `osv-scanner` binary, which natively walks every lockfile
 * ecosystem (package-lock.json, requirements.txt, composer.lock, go.sum, …).
 * This is the only point in the engine that touches the network (public
 * OSV/ecosystem CVE lookups) — per the trust principles.
 *
 * Parsing is best-effort: the JSON shape varies across osv-scanner versions.
 * Severity is bucketed from the scanner's `database_specific.severity` when
 * present, otherwise defaulted to "medium" (a conservative middle). Flag
 * tuning and `groups`-level aliasing are Phase 2 refinements.
 */
import { existsSync } from 'node:fs';
import { commandAvailable, runCommand } from '../proc.mjs';

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
    const stdout = runCommand('osv-scanner', ['--format', 'json', ...targets], { cwd: ctx.repoRoot });
    return parseOsvJson(stdout, ctx.repoRoot);
  },
};

/**
 * Parse `osv-scanner --format json` output into dependency findings.
 * @param {string} stdout
 * @param {string} repoRoot
 * @returns {Finding[]}
 */
function parseOsvJson(stdout, repoRoot) {
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
      const vulns = /** @type {Array<Record<string, any>>} */ (Array.isArray(pkg.vulnerabilities) ? pkg.vulnerabilities : []);
      if (vulns.length === 0) continue;

      /** @type {string[]} */
      const cveIds = [];
      /** @type {string[]} */
      const titles = [];
      let severity = /** @type {Severity} */ ('medium');

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
        message: titles.length > 1 ? `${titles.length} known vulnerabilities` : null,
        fixSummary: version ? `Upgrade ${name} beyond ${version}` : `Upgrade ${name}`,
        source: { provider: 'osv', ruleId: uniqueCves[0] ?? null },
        dependency: { package: name, version, ecosystem, cveIds: uniqueCves },
      });
    }
  }

  return findings;
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
