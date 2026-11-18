// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tenant descriptor — the language/ORM-neutral contract for
 * TD-008 (cross-tenant data leak).
 *
 * Every data-layer parser (Prisma schema, SQL migrations, TypeORM entities,
 * …) emits this same shape; the rule materializer consumes it. Keeping the
 * descriptor in its own module means parsers and the materializer never depend
 * on each other — adding a data layer is adding a parser, not a rewrite.
 */

/**
 * @typedef {Object} TenantDescriptor
 * @property {'column'} mechanism — how tenant isolation is expressed. `column`
 *   for a DB column/FK; future values: `separate-db`, `auth-service`, `unknown`.
 * @property {string} tenantEntity — the aggregate-root model/table name (e.g. `Client`).
 * @property {string[]} scopeColumns — field/column names that scope a record to
 *   its tenant (e.g. `clientId`), matching the ORM field name used in queries.
 * @property {string[] | null} scopedEntities — models carrying the tenant FK
 *   (their data access must filter by a scope column). `null` = unknown.
 * @property {string[] | null} globalEntities — models with no tenant FK (never
 *   flag them). `null` = unknown.
 */

/** Safe identifier shape for a column/model name (prevents YAML/pattern injection). */
export const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Build a normalized tenant descriptor. Invalid identifiers are dropped; a
 * descriptor is unusable (null) without a valid entity and at least one scope
 * column.
 *
 * @param {{ tenantEntity: string, scopeColumns: string[], scopedEntities?: string[] | null, globalEntities?: string[] | null }} input
 * @returns {import('./descriptor.mjs').TenantDescriptor | null}
 */
export function makeDescriptor(input) {
  const tenantEntity = String(input.tenantEntity ?? '').trim();
  const scopeColumns = [
    ...new Set(
      (input.scopeColumns ?? []).map((value) => String(value).trim()).filter((value) => IDENT_RE.test(value)),
    ),
  ];
  if (!IDENT_RE.test(tenantEntity) || scopeColumns.length === 0) return null;

  /** @param {string[] | null | undefined} list @returns {string[] | null} */
  const clean = (list) => {
    if (list == null) return null;
    return [...new Set(list.map((value) => String(value).trim()).filter((value) => IDENT_RE.test(value)))];
  };

  return {
    mechanism: 'column',
    tenantEntity,
    scopeColumns,
    scopedEntities: clean(input.scopedEntities),
    globalEntities: clean(input.globalEntities),
  };
}
