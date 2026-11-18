// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Prisma tenant-discovery parser.
 *
 * Parses `schema.prisma` into a tenant descriptor by building the model
 * relation graph: the tenant is the aggregate root — a model referenced by
 * two or more others via `@relation(fields: […])` and which itself references
 * nothing. Deterministic and offline; reads only the schema text.
 */
import { makeDescriptor } from '../descriptor.mjs';

/** @typedef {import('../descriptor.mjs').TenantDescriptor} TenantDescriptor */

/**
 * One model block: `model Name { … }`. Prisma model bodies never nest
 * braces, so a non-greedy match to the first closing `}` is exact — whether
 * the model is multi-line or a single line.
 */
const MODEL_RE = /\bmodel\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([\s\S]*?)\}/g;

/**
 * One owning-side relation field: `field Model @relation(fields: […], …)`.
 * The model type may carry an optionality `?` (`client Client? @relation(…)`),
 * which the `\??` tolerates. Captures the field name, the referenced model
 * type, and the full relation argument list.
 */
const RELATION_RE =
  /\b([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\??\s+@relation\(([^)]*)\)/g;

const FIELDS_RE = /fields:\s*\[([^\]]+)\]/;

/**
 * Split a comma list (`clientId, orgId`) into trimmed identifiers.
 * @param {string | undefined} raw
 * @returns {string[]}
 */
const splitIds = (raw) =>
  (raw ?? '').split(',').map((value) => value.trim()).filter((value) => value.length > 0);

/**
 * Parse a Prisma schema into a tenant descriptor, or null when no tenant
 * aggregate root can be identified.
 *
 * @param {string} content — full `schema.prisma` text.
 * @returns {TenantDescriptor | null}
 */
export function parsePrismaSchema(content) {
  // Prisma comments are `//` / `///` (whole-line); strip them so a commented
  // example model can't masquerade as a real one.
  const source = content.split(/\r?\n/).filter((line) => !line.trimStart().startsWith('//')).join('\n');

  /** @type {Map<string, Array<{ target: string, fkFields: string[] }>>} model → outgoing relations */
  const outgoing = new Map();
  /** @type {Map<string, Set<string>>} model → models referencing it */
  const incoming = new Map();

  for (const match of source.matchAll(MODEL_RE)) {
    const model = match[1];
    const body = match[2];
    /** @type {Array<{ target: string, fkFields: string[] }>} */
    const relations = [];
    for (const line of body.split(/\r?\n/)) {
      for (const rel of line.matchAll(RELATION_RE)) {
        const target = rel[2];
        const args = rel[3] ?? '';
        const fkFields = splitIds(FIELDS_RE.exec(args)?.[1]);
        if (fkFields.length === 0) continue; // the "one" side of a 1:n — no FK here
        relations.push({ target, fkFields });
      }
    }
    outgoing.set(model, relations);
    for (const relation of relations) {
      if (!incoming.has(relation.target)) incoming.set(relation.target, new Set());
      incoming.get(relation.target)?.add(model);
    }
  }

  // The tenant is the aggregate root: referenced by ≥2 models, referencing none.
  const candidates = [...incoming.entries()]
    .filter(([model, refs]) => refs.size >= 2 && (outgoing.get(model)?.length ?? 0) === 0)
    .sort((a, b) => b[1].size - a[1].size);

  if (candidates.length === 0) return null;
  // Two models tied for the highest in-degree — refuse to guess.
  if (candidates.length > 1 && candidates[0][1].size === candidates[1][1].size) return null;

  const [tenantEntity] = candidates[0];
  /** @type {Set<string>} */
  const scopeColumns = new Set();
  /** @type {Set<string>} */
  const scopedEntities = new Set();
  for (const [model, relations] of outgoing) {
    for (const relation of relations) {
      if (relation.target === tenantEntity) {
        scopedEntities.add(model);
        for (const fk of relation.fkFields) scopeColumns.add(fk);
      }
    }
  }

  const globalEntities = [...outgoing.keys()]
    .filter((model) => model !== tenantEntity && !scopedEntities.has(model));

  return makeDescriptor({
    tenantEntity,
    scopeColumns: [...scopeColumns],
    scopedEntities: [...scopedEntities],
    globalEntities,
  });
}
