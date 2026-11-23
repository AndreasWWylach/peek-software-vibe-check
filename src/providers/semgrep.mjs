// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Semgrep provider — runs the engine's custom `rules/peek/**`
 * (teardown) and `rules/hygiene/**` (always-on hygiene) rules.
 *
 * Rule enablement = the TD is enabled in the config AND a rule variant exists
 * for a detected language (the intersection described in docs §5.5). Each rule
 * carries `metadata.peek` ({ teardownId, pillar, severity, fixSummary }) so the
 * provider can map results to findings without re-reading the catalog; the
 * catalog still enriches `fixSummary` when a fact is vendored.
 *
 * Hygiene rules are always-on hardening checks mapped from the LastMile
 * framework. They carry `metadata.peek.hygiene = true` (with `ruleId`, `pillar`,
 * `severity`, `title`, `fixSummary`) and produce `kind: 'hygiene'` findings with
 * `teardownId = null` — they are scored, but tied to no single teardown fact.
 *
 * With zero vendored rules (Phase 1) this provider discovers nothing and
 * returns no findings.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommand } from '../proc.mjs';
import { enrichTeardowns } from '../catalog.mjs';
import { isIgnoredDir, isVendoredPath } from '../ignore.mjs';
import { readLine, shouldSkipSecret } from '../secretClassify.mjs';
import { materializeTenantRule, readTenantColumn } from './tenant-rule.mjs';
import { discoverTenant, guidanceFor } from '../tenant/discover.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */

/** Absolute path to the custom rules root (`rules/peek/<TD-id>/<lang>.yaml`). */
const RULES_ROOT = fileURLToPath(new URL('../../rules/peek', import.meta.url));
/** Absolute path to the always-on hygiene rules root (`rules/hygiene/*.yaml`). */
const HYGIENE_ROOT = fileURLToPath(new URL('../../rules/hygiene', import.meta.url));

/** Absolute root of the vendored Semgrep PHP packs (`rules/vendored/php/*`). */
const VENDORED_PHP_ROOT = fileURLToPath(new URL('../../rules/vendored/php', import.meta.url));

/**
 * Vendored Semgrep PHP rule id → teardown, for **taint-proven** deterministic
 * defects only. Presence-of-sink rules (`exec-use`, `backticks-use`,
 * `doctrine-dbal-dangerous-query`, `wp-*-audit`) are heuristics — they stay
 * hygiene advisories rather than inflating the score on code that legitimately
 * shells out.
 */
const VENDORED_TD_MAP = /** @type {Array<{ re: RegExp; teardownId: string }>} */ ([
  {
    re: /tainted-sql-string|laravel-sql-injection|laravel-api-route-sql-injection|doctrine-orm-dangerous-query/i,
    teardownId: 'TD-033', // SQL injection (mode: taint)
  },
  { re: /tainted-exec/i, teardownId: 'TD-042' }, // command injection (mode: taint)
  { re: /tainted-url-host/i, teardownId: 'TD-057' }, // SSRF — user-controlled URL host (mode: taint)
]);

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
 * Discover always-on hygiene rule files for the config's detected languages.
 * @param {ScanConfig} config
 * @returns {string[]} absolute paths to `.yaml` rule files (sorted, deterministic).
 */
function discoverHygieneRules(config) {
  if (!existsSync(HYGIENE_ROOT)) return [];

  const languages = new Set(config.languages.map((language) => language.toLowerCase()));
  /** @type {string[]} */
  const files = [];

  for (const file of readdirSync(HYGIENE_ROOT)) {
    if (!file.endsWith('.yaml')) continue;
    const declared = declaredLanguages(join(HYGIENE_ROOT, file));
    if (languages.size === 0 || declared.some((lang) => languages.has(lang))) {
      files.push(join(HYGIENE_ROOT, file));
    }
  }
  return files.sort();
}

/**
 * Discover vendored Semgrep PHP rule files for the app's PHP + framework.
 * `lang` always applies to PHP; the framework packs apply when the matching
 * marker is detected (`laravel`, `symfony`/`pimcore`, `doctrine`, or a root
 * `wp-config.php` for WordPress). Returns absolute `.yaml` paths (sorted).
 * @param {ScanConfig} config
 * @param {RunContext} ctx
 * @returns {string[]}
 */
function discoverVendoredPhpRules(config, ctx) {
  const hasPhp = config.languages.some((language) => language.toLowerCase() === 'php');
  if (!hasPhp || !existsSync(VENDORED_PHP_ROOT)) return [];

  const stack = ctx.stack ?? {};
  const packs = ['lang'];
  if (stack.laravel) packs.push('laravel');
  if (stack.symfony || stack.pimcore) packs.push('symfony');
  if (stack.doctrine) packs.push('doctrine');
  if (existsSync(join(ctx.repoRoot, 'wp-config.php'))) packs.push('wordpress');

  /** @type {string[]} */
  const files = [];
  for (const pack of packs) {
    const dir = join(VENDORED_PHP_ROOT, pack);
    if (!existsSync(dir)) continue;
    collectYamlFiles(dir, files);
  }
  ctx.log(`  vendored PHP rulesets: ${packs.join(', ')}`);
  return files.sort();
}

/**
 * Recursively collect `.yaml` rule files under a vendored pack dir.
 * @param {string} dir
 * @param {string[]} out
 */
function collectYamlFiles(dir, out) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) collectYamlFiles(abs, out);
    else if (entry.isFile() && entry.name.endsWith('.yaml')) out.push(abs);
  }
}

/**
 * Normalize a semgrep `check_id` to a machine-independent rule id.
 *
 * Semgrep derives `check_id` from the rule file's absolute path (`/`→`.`, no
 * `.yaml`), which embeds the machine path and breaks cross-machine
 * determinism. We strip everything up to the engine's `rules/` root so the id
 * is stable: `…/rules/vendored/php/lang/security/weak-crypto.yaml` →
 * `vendored.php.lang.security.weak-crypto`.
 * @param {string} checkId
 * @returns {string}
 */
export function normalizeCheckId(checkId) {
  const marker = '.rules.';
  const idx = checkId.lastIndexOf(marker);
  return idx === -1 ? checkId : checkId.slice(idx + marker.length);
}

/**
 * The normalized check_id a vendored rule file will produce in semgrep output.
 * @param {string} file — absolute path to a `.yaml` rule file.
 * @returns {string}
 */
function normalizedIdForFile(file) {
  const dotted = file.replace(/\\/g, '/').replace(/^\//, '').replace(/\//g, '.').replace(/\.yaml$/, '');
  return normalizeCheckId(dotted);
}

/**
 * Map a vendored rule FILE to a teardown, or null when it stays an advisory.
 * @param {string} file — absolute path to a `.yaml` rule file.
 * @returns {string | null}
 */
export function classifyVendoredFile(file) {
  for (const { re, teardownId } of VENDORED_TD_MAP) {
    if (re.test(file)) return teardownId;
  }
  return null;
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
    const hygieneFiles = discoverHygieneRules(config);
    const vendoredFiles = discoverVendoredPhpRules(config, ctx);
    /** normalized check_id → teardownId, for the vendored deterministic defects. */
    const vendoredTeardowns = new Map();
    for (const file of vendoredFiles) {
      const teardownId = classifyVendoredFile(file);
      if (teardownId) vendoredTeardowns.set(normalizedIdForFile(file), teardownId);
    }

    // TD-008 tenant sharpening: use the config's explicit tenant column when
    // present, else DISCOVER the tenant entity (aggregate root) from the app's
    // data layer. The config stays inert — only column names are read.
    const hasGenericRule = ruleFiles.some((file) => file.endsWith(join('TD-008', 'typescript.yaml')));
    if (hasGenericRule) {
      const withoutGeneric = ruleFiles.filter(
        (file) => !file.endsWith(join('TD-008', 'typescript.yaml')),
      );
      const explicitColumn = readTenantColumn(config);
      const discovery = explicitColumn ? null : discoverTenant(ctx);

      if (explicitColumn) {
        ruleFiles = [
          ...withoutGeneric,
          materializeTenantRule([explicitColumn], null, process.env.VIBE_CHECK_RULE_DIR),
        ];
        ctx.log(`  TD-008 tenant scope: ${explicitColumn} (from config)`);
      } else if (discovery?.descriptor) {
        const descriptor = discovery.descriptor;
        if (discovery.dataLayer === 'sql') {
          // Raw SQL is not yet checkable by the Prisma query rule — report the
          // discovered tenant root honestly instead of pretending it was checked.
          ruleFiles = withoutGeneric;
          ctx.noteNotVerifiable?.('TD-008', 'Query without tenant scope', guidanceFor('sql-not-checkable', descriptor.tenantEntity));
          ctx.log(
            `  TD-008: SQL tenant root ${descriptor.tenantEntity} detected — raw-SQL scoping not yet auto-checkable`,
          );
        } else {
          ruleFiles = [
            ...withoutGeneric,
            materializeTenantRule(descriptor.scopeColumns, descriptor.scopedEntities, process.env.VIBE_CHECK_RULE_DIR),
          ];
          ctx.log(
            `  TD-008 tenant scope: ${descriptor.tenantEntity} → ${descriptor.scopeColumns.join(', ')} (auto-detected; scoped ${descriptor.scopedEntities?.length ?? '?'} model(s))`,
          );
        }
      } else {
        const reason = discovery?.notVerifiable ?? 'no-parseable-data-layer';
        ruleFiles = withoutGeneric;
        ctx.noteNotVerifiable?.('TD-008', 'Query without tenant scope', guidanceFor(reason));
        ctx.log(`  TD-008: ${reason} — reported as not statically verifiable`);
      }
    }

    if (ruleFiles.length === 0 && hygieneFiles.length === 0 && vendoredFiles.length === 0) {
      ctx.log('  no enabled rules with matching variants — nothing to scan');
      return [];
    }

    /** @type {string[]} */
    const args = [];
    for (const file of [...ruleFiles, ...hygieneFiles, ...vendoredFiles]) {
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
    const findings = parseSemgrepJson(stdout, ctx.repoRoot)
      .filter((finding) => !isIgnoredDir(finding.file) && !isVendoredPath(finding.file))
      .filter((finding) => !isClassifiedSecret(finding, ctx.repoRoot));
    // Promote vendored rules that map to a deterministic-defect teardown
    // (SQLi / command injection) from advisory hygiene to scored teardowns.
    for (const finding of findings) {
      const ruleId = finding.source.ruleId;
      if (ruleId) {
        const teardownId = vendoredTeardowns.get(ruleId);
        if (teardownId) {
          finding.kind = 'teardown';
          finding.teardownId = teardownId;
          finding.advisory = false;
        }
      }
    }
    return enrichTeardowns(findings);
  },
};

/**
 * TD-016 findings from ANY provider go through the same secret classifier
 * (gitleaks, trivy, and now semgrep) so they agree on what is a real secret:
 * placeholder examples, `changeme`, alphabet constants and public-by-design
 * keys are skipped, never reported — the engine's own detector docs contain
 * `sk_test_placeholder` examples that would otherwise score against itself.
 * @param {Finding} finding
 * @param {string} repoRoot
 * @returns {boolean} true when the finding is a classified non-secret.
 */
export function isClassifiedSecret(finding, repoRoot) {
  if (finding.teardownId !== 'TD-016' || finding.line == null) return false;
  const abs = isAbsolute(finding.file) ? finding.file : join(repoRoot, finding.file);
  return shouldSkipSecret(readLine(abs, finding.line), abs);
}

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
  const checkId = normalizeCheckId(String(result.check_id ?? 'unknown'));
  const extra = /** @type {Record<string, any>} */ (result.extra ?? {});
  const metadata = /** @type {Record<string, any>} */ (extra.metadata ?? {});
  const peek = /** @type {Record<string, any>} */ (metadata.peek ?? {});

  // External/vendored rules (no `metadata.peek`) default to hygiene advisories;
  // our custom rules carry `metadata.peek` with an explicit contract.
  const hasPeek = 'peek' in metadata && metadata.peek !== null && typeof metadata.peek === 'object';
  const teardownId = hasPeek && typeof peek.teardownId === 'string' ? peek.teardownId : null;
  const hygiene = hasPeek ? peek.hygiene === true : true;
  const severity = /** @type {Severity} */ (
    (hasPeek ? peek.severity : undefined) ?? SEMGREP_SEVERITY[String(extra.severity ?? 'INFO')] ?? 'low'
  );
  const pillar = /** @type {Pillar} */ (hasPeek ? (peek.pillar ?? 'qa') : 'security');
  const line = /** @type {number | null} */ (result.start?.line ?? null);
  const column = /** @type {number | null} */ (result.start?.col ?? null);

  const absolutePath = String(result.path ?? '');
  const file = absolutePath.startsWith(repoRoot)
    ? absolutePath.slice(repoRoot.length).replace(/^[/\\]+/, '')
    : absolutePath;

  const title = typeof peek.title === 'string' ? peek.title : String(extra.message ?? checkId);
  const fixSummary = typeof peek.fixSummary === 'string' ? peek.fixSummary : null;

  // Hygiene rules carry `metadata.peek.hygiene = true` and `ruleId` instead of a
  // `teardownId`; they map to `kind: 'hygiene'` findings (scored, no catalog fact).
  const sourceRuleId = hygiene ? String(peek.ruleId ?? checkId) : checkId;
  const findingId = `${hygiene ? sourceRuleId : (teardownId ?? checkId)}:${file}:${line ?? 0}:${column ?? 0}`;

  return {
    id: findingId,
    kind: hygiene ? 'hygiene' : 'teardown',
    file,
    line,
    column,
    severity,
    pillar,
    teardownId: hygiene ? null : teardownId,
    title,
    message: typeof extra.message === 'string' ? extra.message : null,
    fixSummary,
    source: { provider: 'semgrep', ruleId: sourceRuleId },
    dependency: null,
    // A rule may opt in to advisory (report-but-don't-score) via `peek.advisory`
    // — used for weak hygiene signals that are policy judgments, not defects.
    // External/vendored rules are advisory until classified (see run()).
    advisory: hasPeek ? peek.advisory === true : true,
  };
}
