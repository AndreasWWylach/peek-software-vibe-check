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
import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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
 * Build the materialized TD-008 rule YAML for a specific tenant column.
 *
 * Replaces the generic hardcoded column list with the ONE configured column
 * (and its Prisma compound-key form `id_<column>`). The config never sees this
 * YAML - it only carries the inert column name.
 *
 * @param {string} column - validated identifier (e.g. "organizationId").
 * @returns {string} the rule YAML.
 */
export function buildTenantRuleYaml(column) {
  const compound = `id_${column}`;
  const queryPatterns = METHODS.map(
    (method) => `          - pattern: '$PRISMA.$MODEL.${method}({..., where: $WHERE, ...})'`,
  ).join('\n');

  return [
    'rules:',
    '  - id: peek-td-008-idor-unscoped-lookup-tenant-typescript',
    '    languages:',
    '      - typescript',
    '      - javascript',
    '    severity: ERROR',
    `    message: Prisma data query lacks explicit ${column} tenant scope.`,
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
    `      - pattern-not: '$PRISMA.$MODEL.$METHOD({..., where: { ${column}: $ANY, ... }, ...})'`,
    `      - pattern-not: '$PRISMA.$MODEL.$METHOD({..., where: { ${compound}: $ANY, ... }, ...})'`,
    '',
  ].join('\n');
}

/**
 * Materialize the tenant-scoped TD-008 rule into a YAML file and return its path.
 * @param {string} column - validated tenant column.
 * @param {string} [dir] - target directory (defaults to a fresh OS temp dir).
 * @returns {string} absolute path to the generated `.yaml` rule file.
 */
export function materializeTenantRule(column, dir = join(tmpdir(), 'vibe-check-rules')) {
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `td-008-tenant-${column}.yaml`);
  writeFileSync(file, buildTenantRuleYaml(column), 'utf8');
  return file;
}
