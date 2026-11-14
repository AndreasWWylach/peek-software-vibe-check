// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Semgrep provider — runs the engine's custom `rules/peek/**` rules.
 *
 * Rule enablement = the TD is enabled in the config AND a rule variant exists
 * for a detected language (the intersection described in docs §5.5). Each rule
 * carries `metadata.peek` ({ teardownId, pillar, severity, fixSummary }) so the
 * provider can map results to findings without re-reading the catalog; the
 * catalog still enriches `fixSummary` when a fact is vendored.
 *
 * With zero vendored rules (Phase 1) this provider discovers nothing and
 * returns no findings.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommand } from '../proc.mjs';
import { lookupTeardown } from '../catalog.mjs';
import { materializeTenantRule, readTenantColumn } from './tenant-rule.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */

/** Absolute path to the custom rules root (`rules/peek/<TD-id>/<lang>.yaml`). */
const RULES_ROOT = fileURLToPath(new URL('../../rules/peek', import.meta.url));

/** Map Semgrep's severity strings to our shared severity enum (fallback only). */
const SEMGREP_SEVERITY = /** @type {Record<string, Severity>} */ ({
  ERROR: 'high',
  WARNING: 'medium',
  INFO: 'low',
});

/**
 * Discover rule files whose TD is enabled and whose language is detected.
 * @param {ScanConfig} config
 * @returns {string[]} absolute paths to `.yaml` rule files (sorted, deterministic).
 */
function discoverRules(config) {
  const enabled = new Set(config.enabledRules);
  if (enabled.size === 0 || !existsSync(RULES_ROOT)) return [];

  const languages = new Set(config.languages.map((language) => language.toLowerCase()));
  /** @type {string[]} */
  const files = [];

  for (const tdId of readdirSync(RULES_ROOT)) {
    if (!enabled.has(tdId)) continue;
    const tdDir = join(RULES_ROOT, tdId);
    if (!existsSync(tdDir)) continue;
    for (const file of readdirSync(tdDir)) {
      if (!file.endsWith('.yaml')) continue;
      // A variant applies when the config lists any of its declared languages
      // (or lists none). Rules may target several languages — e.g. a TypeScript
      // rule that also matches plain JavaScript — so we read the rule's own
      // `languages:` block rather than guessing from the file name.
      const declared = declaredLanguages(join(tdDir, file));
      if (languages.size === 0 || declared.some((lang) => languages.has(lang))) {
        files.push(join(tdDir, file));
      }
    }
  }
  return files.sort();
}

/**
 * The languages a rule file declares across all of its `languages:` blocks.
 * Falls back to the file name (e.g. `typescript.yaml`) when no block is found.
 * @param {string} file
 * @returns {string[]}
 */
function declaredLanguages(file) {
  /** @type {Set<string>} */
  const langs = new Set();
  try {
    const text = readFileSync(file, 'utf8');
    for (const block of text.matchAll(/languages:\s*((?:\s*-\s*\w+\s*)+)/g)) {
      for (const item of block[1].matchAll(/-\s*(\w+)/g)) langs.add(item[1].toLowerCase());
    }
  } catch {
    // Unreadable file — fall back to the file name below.
  }
  if (langs.size === 0) langs.add(file.slice(file.lastIndexOf('/') + 1, -'.yaml'.length).toLowerCase());
  return [...langs];
}

/** @type {Provider} */
export const semgrepProvider = {
  id: 'semgrep',
  name: 'Semgrep',
  available: () => commandAvailable('semgrep'),
  applicable: () => true,
  async run(config, ctx) {
    let ruleFiles = discoverRules(config);

    // v2 parameterization: when the config names a tenant column, replace the
    // generic TD-008 TypeScript rule with a precise materialization requiring
    // exactly that column (the config stays inert — only the column name is
    // read, never rule code).
    const tenantColumn = readTenantColumn(config);
    if (tenantColumn) {
      const withoutGeneric = ruleFiles.filter(
        (file) => !file.endsWith(join('TD-008', 'typescript.yaml')),
      );
      if (withoutGeneric.length < ruleFiles.length) {
        // `VIBE_CHECK_RULE_DIR` (optional) lets a host point the materialized
        // rule at a path its semgrep can reach — e.g. a container mount that
        // doesn't include /tmp. Defaults to the OS temp dir.
        ruleFiles = [...withoutGeneric, materializeTenantRule(tenantColumn, process.env.VIBE_CHECK_RULE_DIR)];
        ctx.log(`  TD-008 tenant scope: ${tenantColumn}`);
      }
    }

    if (ruleFiles.length === 0) {
      ctx.log('  no enabled rules with matching variants — nothing to scan');
      return [];
    }

    /** @type {string[]} */
    const args = [];
    for (const file of ruleFiles) {
      args.push('--config', file);
    }
    // `--no-git-ignore` makes semgrep scan exactly the targeted paths — it
    // neither limits to git-tracked files nor skips gitignored ones, so the
    // audit is transparent about what it scanned (no hidden omissions).
    args.push('--json', '--no-git-ignore');

    for (const target of ctx.targets) {
      if (existsSync(target)) {
        args.push(target);
      } else {
        ctx.log(`  warning: target not found, skipping: ${target}`);
      }
    }

    // No existing targets → nothing for semgrep to scan.
    if (!args.some((arg) => !arg.startsWith('--'))) return [];

    const stdout = runCommand('semgrep', args, { cwd: ctx.repoRoot });
    return enrichFromCatalog(parseSemgrepJson(stdout, ctx.repoRoot));
  },
};

/**
 * Parse `semgrep --json` output into findings.
 * @param {string} stdout
 * @param {string} repoRoot
 * @returns {Finding[]}
 */
export function parseSemgrepJson(stdout, repoRoot) {
  const parsed = JSON.parse(stdout);
  const results = /** @type {Array<Record<string, any>>} */ (Array.isArray(parsed.results) ? parsed.results : []);
  return results.map((result) => toFinding(result, repoRoot));
}

/**
 * Convert one semgrep result into a finding.
 * @param {Record<string, any>} result
 * @param {string} repoRoot
 * @returns {Finding}
 */
function toFinding(result, repoRoot) {
  const checkId = String(result.check_id ?? 'unknown');
  const extra = /** @type {Record<string, any>} */ (result.extra ?? {});
  const metadata = /** @type {Record<string, any>} */ (extra.metadata ?? {});
  const peek = /** @type {Record<string, any>} */ (metadata.peek ?? {});

  const teardownId = typeof peek.teardownId === 'string' ? peek.teardownId : null;
  const severity = /** @type {Severity} */ (
    peek.severity ?? SEMGREP_SEVERITY[String(extra.severity ?? 'INFO')] ?? 'low'
  );
  const pillar = /** @type {Pillar} */ (peek.pillar ?? 'qa');
  const line = /** @type {number | null} */ (result.start?.line ?? null);
  const column = /** @type {number | null} */ (result.start?.col ?? null);

  const absolutePath = String(result.path ?? '');
  const file = absolutePath.startsWith(repoRoot)
    ? absolutePath.slice(repoRoot.length).replace(/^[/\\]+/, '')
    : absolutePath;

  const title = typeof peek.title === 'string' ? peek.title : String(extra.message ?? checkId);
  const fixSummary = typeof peek.fixSummary === 'string' ? peek.fixSummary : null;

  return {
    id: `${teardownId ?? checkId}:${file}:${line ?? 0}:${column ?? 0}`,
    kind: 'teardown',
    file,
    line,
    column,
    severity,
    pillar,
    teardownId,
    title,
    message: typeof extra.message === 'string' ? extra.message : null,
    fixSummary,
    source: { provider: 'semgrep', ruleId: checkId },
    dependency: null,
  };
}

/**
 * Enrich teardown findings with vendored catalog facts (fixSummary etc.).
 * @param {Finding[]} findings
 * @returns {Promise<Finding[]>}
 */
async function enrichFromCatalog(findings) {
  for (const finding of findings) {
    if (!finding.teardownId) continue;
    const fact = await lookupTeardown(finding.teardownId);
    if (!fact) continue;
    finding.fixSummary = finding.fixSummary ?? fact.fixSummary;
    finding.severity = fact.severity;
    finding.pillar = fact.pillar;
  }
  return findings;
}
