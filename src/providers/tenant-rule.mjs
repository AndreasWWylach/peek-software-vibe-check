// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tenant-column rule materialization (TD-008 parameterization, v2).
 *
 * The config is inert data (trust principle). `ruleParams.tenantColumn` names
 * the app's tenant-scope column; at scan time the engine materializes a precise
 * TD-008 rule — requiring exactly that column — from a template. The config
 * never carries rule code.
 */
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative } from 'node:path';
import { hasNonCodeExt, isIgnoredDir } from '../ignore.mjs';

/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */

/** Structural type for the slice of the config this module reads. */
/**
 * @typedef {{ ruleParams?: { tenantColumn?: unknown } }} TenantParamConfig
 */

/** Safe identifier shape for a column name (prevents YAML/pattern injection). */
export const TENANT_COLUMN_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** The Prisma data-access methods TD-008 covers. */
const METHODS = ['findUnique', 'findFirst', 'findMany', 'update', 'updateMany', 'delete', 'deleteMany'];

/**
 * Read + validate the tenant column from the config.
 * @param {TenantParamConfig} config
 * @returns {string | null} the validated column name, or null when absent/invalid.
 */
export function readTenantColumn(config) {
  const value = config.ruleParams?.tenantColumn;
  if (typeof value !== 'string') return null;
  const column = value.trim();
  return TENANT_COLUMN_RE.test(column) ? column : null;
}

/**
 * Tenant-like column names found in schema/model files (camelCase or snake_case).
 * Deliberately excludes `userId` (a user, not a tenant) and `client` (OAuth
 * `client_id` is not tenant scope) — only strong tenant prefixes.
 */
const TENANT_COLUMN_NAME_RE =
  /\b(?:tenant|org|organization|workspace|company|team|customer|account)[_-]?id\b/gi;

/**
 * Normalize one column or a list into a sorted, deduped, validated list.
 * @param {string | string[]} columnOrColumns
 * @returns {string[]}
 */
function normalizeColumns(columnOrColumns) {
  const list = Array.isArray(columnOrColumns) ? columnOrColumns : [columnOrColumns];
  return [...new Set(list.map((value) => String(value).trim()).filter((value) => TENANT_COLUMN_RE.test(value)))].sort();
}

/**
 * Build the materialized TD-008 rule YAML for one or more tenant columns.
 *
 * Replaces the generic hardcoded column list with the configured (or
 * auto-detected) columns and their Prisma compound-key forms `id_<column>`.
 * The config never sees this YAML - it only carries the inert column name(s).
 *
 * @param {string | string[]} columnOrColumns - validated identifier(s), e.g.
 *   "organizationId" or ["organizationId", "workspaceId"].
 * @returns {string} the rule YAML.
 */
export function buildTenantRuleYaml(columnOrColumns) {
  const columns = normalizeColumns(columnOrColumns);
  if (columns.length === 0) {
    throw new Error('buildTenantRuleYaml: no valid tenant column(s)');
  }
  const queryPatterns = METHODS.map(
    (method) => `          - pattern: '$PRISMA.$MODEL.${method}({..., where: $WHERE, ...})'`,
  ).join('\n');
  const scope = columns.length === 1
    ? `lacks explicit ${columns[0]} tenant scope`
    : `lacks tenant scope (expected one of: ${columns.join(', ')})`;

  const patternNots = columns.flatMap((column) => [
    `      - pattern-not: '$PRISMA.$MODEL.$METHOD({..., where: { ${column}: $ANY, ... }, ...})'`,
    `      - pattern-not: '$PRISMA.$MODEL.$METHOD({..., where: { id_${column}: $ANY, ... }, ...})'`,
  ]);

  return [
    'rules:',
    '  - id: peek-td-008-idor-unscoped-lookup-tenant-typescript',
    '    languages:',
    '      - typescript',
    '      - javascript',
    '    severity: ERROR',
    // Quote the message: the multi-column scope lists columns after a colon
    // ("expected one of: a, b"), which would otherwise parse as a YAML mapping.
    `    message: "Prisma data query ${scope}."`,
    '    metadata:',
    '      peek:',
    '        teardownId: TD-008',
    '        pillar: security',
    '        severity: critical',
    '        title: Query without tenant scope',
    '        fixSummary: Scope every query to the authenticated tenant via a compound key or a tenant filter.',
    '      category: security',
    '    patterns:',
    '      - pattern-either:',
    queryPatterns,
    ...patternNots,
    '',
  ].join('\n');
}

/**
 * Materialize the tenant-scoped TD-008 rule into a YAML file and return its path.
 * @param {string | string[]} columnOrColumns - validated tenant column(s).
 * @param {string} [dir] - target directory (defaults to a fresh OS temp dir).
 * @returns {string} absolute path to the generated `.yaml` rule file.
 */
export function materializeTenantRule(columnOrColumns, dir = join(tmpdir(), 'vibe-check-rules')) {
  const columns = normalizeColumns(columnOrColumns);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `td-008-tenant-${columns.join('-')}.yaml`);
  writeFileSync(file, buildTenantRuleYaml(columns), 'utf8');
  return file;
}

/**
 * Auto-detect the app's tenant-scope column(s) from its own source. Reads only
 * the scanned targets (schema, migrations, models, and query code) — never asks
 * the user. Deterministic and offline.
 * @param {import('../types.mjs').RunContext} ctx
 * @returns {string[]} sorted, deduped, validated column names.
 */
export function detectTenantColumns(ctx) {
  /** @type {Set<string>} */
  const found = new Set();
  for (const target of ctx.targets) {
    collectTenantCandidates(target, ctx.repoRoot, found);
  }
  return [...found].filter((column) => TENANT_COLUMN_RE.test(column)).sort();
}

/**
 * Recursively walk a directory, collecting tenant-like identifiers from files.
 * @param {string} dir - absolute directory.
 * @param {string} repoRoot
 * @param {Set<string>} found
 */
function collectTenantCandidates(dir, repoRoot, found) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (isIgnoredDir(entry.name)) continue;
      collectTenantCandidates(abs, repoRoot, found);
    } else if (entry.isFile()) {
      const repoFile = isAbsolute(abs) ? relative(repoRoot, abs).replace(/^[/\\]+/, '') : abs;
      if (isIgnoredDir(repoFile) || hasNonCodeExt(repoFile)) continue;
      let text = '';
      try {
        text = readFileSync(abs, 'utf8');
      } catch {
        continue;
      }
      for (const match of text.matchAll(TENANT_COLUMN_NAME_RE)) found.add(match[0]);
    }
  }
}
