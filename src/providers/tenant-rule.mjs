// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tenant rule materialization (TD-008 parameterization).
 *
 * The config is inert data (trust principle). Discovery (see `src/tenant/`)
 * produces a tenant descriptor; this module turns that inert data into a
 * precise TD-008 rule — requiring exactly the discovered scope column(s) and
 * restricted to the tenant-scoped entities. The config never carries rule code.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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
 * Replaces the generic hardcoded column list with the discovered (or
 * configured) columns and their Prisma compound-key forms `id_<column>`. When
 * `scopedEntities` is provided, `$MODEL` is restricted to those models so
 * deliberately global entities (e.g. a shared catalog) are never flagged.
 *
 * @param {string | string[]} columnOrColumns - validated identifier(s), e.g.
 *   "organizationId" or ["organizationId", "workspaceId"].
 * @param {string[] | null} [scopedEntities] - tenant-scoped model names; null
 *   (default) = every model.
 * @returns {string} the rule YAML.
 */
export function buildTenantRuleYaml(columnOrColumns, scopedEntities = null) {
  const columns = normalizeColumns(columnOrColumns);
  if (columns.length === 0) {
    throw new Error('buildTenantRuleYaml: no valid tenant column(s)');
  }
  // Prisma exposes models via a lowercase-first accessor (`RequestLog` →
  // `prisma.requestLog`). When the tenant-scoped entities are known, enumerate
  // them explicitly (per model × method) so a deliberately global model can
  // never fire. Unknown scope → fall back to the generic `$MODEL`.
  /** @param {string} name @returns {string} */
  const toAccessor = (name) => name.charAt(0).toLowerCase() + name.slice(1);
  const accessors = scopedEntities && scopedEntities.length > 0 ? scopedEntities.map(toAccessor) : null;

  const queryPatterns = accessors
    ? accessors
        .flatMap((model) =>
          METHODS.map(
            (method) => `          - pattern: '$PRISMA.${model}.${method}({..., where: $WHERE, ...})'`,
          ),
        )
        .join('\n')
    : METHODS.map(
        (method) => `          - pattern: '$PRISMA.$MODEL.${method}({..., where: $WHERE, ...})'`,
      ).join('\n');

  const scope = columns.length === 1
    ? `lacks explicit ${columns[0]} tenant scope`
    : `lacks tenant scope (expected one of: ${columns.join(', ')})`;

  const modelRefs = accessors ?? ['$MODEL'];
  const patternNots = modelRefs.flatMap((model) =>
    columns.flatMap((column) => [
      `      - pattern-not: '$PRISMA.${model}.$METHOD({..., where: { ${column}: $ANY, ... }, ...})'`,
      `      - pattern-not: '$PRISMA.${model}.$METHOD({..., where: { id_${column}: $ANY, ... }, ...})'`,
    ]),
  );

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
 * @param {string[] | null} [scopedEntities] - tenant-scoped model names to
 *   restrict `$MODEL` to (null = every model).
 * @param {string} [dir] - target directory (defaults to a fresh OS temp dir).
 * @returns {string} absolute path to the generated `.yaml` rule file.
 */
export function materializeTenantRule(columnOrColumns, scopedEntities = null, dir = join(tmpdir(), 'vibe-check-rules')) {
  const columns = normalizeColumns(columnOrColumns);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `td-008-tenant-${columns.join('-')}.yaml`);
  writeFileSync(file, buildTenantRuleYaml(columns, scopedEntities), 'utf8');
  return file;
}
