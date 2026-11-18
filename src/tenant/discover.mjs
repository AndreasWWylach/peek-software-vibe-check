// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tenant discovery dispatch.
 *
 * Picks the right data-layer parser from the app's detected stack markers and
 * returns a normalized tenant descriptor — or an honest "not verifiable" reason
 * when no parser applies or no tenant can be identified. Language/ORM-agnostic:
 * adding a data layer = adding a parser behind the marker, never a rewrite.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { isIgnoredDir } from '../ignore.mjs';
import { parsePrismaSchema } from './parsers/prisma.mjs';

/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('./descriptor.mjs').TenantDescriptor} TenantDescriptor */

/**
 * Discover the app's tenant identity (aggregate root + scope columns).
 *
 * @param {RunContext} ctx
 * @returns {{ descriptor?: TenantDescriptor, notVerifiable?: string }}
 */
export function discoverTenant(ctx) {
  const stack = ctx.stack ?? {};
  if (stack.prisma) {
    const schema = findFile(ctx, 'schema.prisma');
    if (!schema) return { notVerifiable: 'prisma-schema-not-found' };
    const descriptor = parsePrismaSchema(readFileSync(schema, 'utf8'));
    return descriptor ? { descriptor } : { notVerifiable: 'no-tenant-entity' };
  }
  // No parseable data layer yet (SQL migrations, TypeORM, Mongoose, … land
  // here as more parsers ship). Be honest rather than silent.
  return { notVerifiable: 'no-parseable-data-layer' };
}

/**
 * Human guidance for a discovery reason code (surfaced in the report).
 *
 * @param {string} reason
 * @returns {string}
 */
export function guidanceFor(reason) {
  switch (reason) {
    case 'prisma-schema-not-found':
      return 'A Prisma app was detected but schema.prisma was not found in the scan targets, so tenant isolation could not be checked. Set ruleParams.tenantColumn to check a specific column.';
    case 'no-tenant-entity':
      return 'Tenant data may be present but no tenant entity could be identified (no model referenced by two or more others). Review data-access paths manually, or set ruleParams.tenantColumn to check a specific column.';
    case 'no-parseable-data-layer':
      return "Tenant isolation could not be verified automatically: the app's data-access layer is not yet parseable by the scanner (e.g. raw SQL, TypeORM, Mongoose, or an auth service). Review data-access paths manually, or set ruleParams.tenantColumn.";
    default:
      return 'Tenant isolation could not be verified.';
  }
}

/**
 * Find the first file with a given basename under the scan targets.
 * @param {RunContext} ctx
 * @param {string} basename
 * @returns {string | null} absolute path, or null.
 */
function findFile(ctx, basename) {
  for (const target of ctx.targets) {
    const found = walkFor(target, basename);
    if (found) return found;
  }
  return null;
}

/** @param {string} dir @param {string} basename @returns {string | null} */
function walkFor(dir, basename) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (isIgnoredDir(entry.name)) continue;
      const found = walkFor(abs, basename);
      if (found) return found;
    } else if (entry.name === basename) {
      return abs;
    }
  }
  return null;
}
