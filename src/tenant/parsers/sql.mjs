// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview SQL-migrations tenant-discovery parser.
 *
 * Parses `CREATE TABLE` DDL (across one or more migration files) into a tenant
 * descriptor by building the same relation graph the Prisma parser builds: the
 * tenant is the aggregate root — a table referenced by two or more others via
 * `FOREIGN KEY … REFERENCES` (table- or column-level) and which itself
 * references nothing. Deterministic and offline; reads only migration text.
 */
import { makeDescriptor } from '../descriptor.mjs';

/** @typedef {import('../descriptor.mjs').TenantDescriptor} TenantDescriptor */

/** `CREATE TABLE [IF NOT EXISTS] [schema.]name (` — captures optional schema + table. */
export const CREATE_TABLE_RE =
  /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("?[A-Za-z_][A-Za-z0-9_]*"?)(?:\s*\.\s*("?[A-Za-z_][A-Za-z0-9_]*"?))?\s*\(/gi;

/** Table-level FK: `[CONSTRAINT x] FOREIGN KEY (cols) REFERENCES [schema.]table(cols)`. */
const TABLE_FK_RE =
  /\bFOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+(?:"?([A-Za-z_][A-Za-z0-9_]*)"?\s*\.\s*)?("?[A-Za-z_][A-Za-z0-9_]*"?)\s*\(([^)]+)\)/i;

/** Column-level FK: `col TYPE … REFERENCES [schema.]table(cols)`. */
const INLINE_REF_RE =
  /\bREFERENCES\s+(?:"?([A-Za-z_][A-Za-z0-9_]*)"?\s*\.\s*)?("?[A-Za-z_][A-Za-z0-9_]*"?)\s*\(([^)]+)\)/i;

/** A column definition's leading identifier: `client_id BIGINT …`. */
const LEADING_COLUMN_RE = /^\s*("?[A-Za-z_][A-Za-z0-9_]*"?)/;

/**
 * Strip SQL comments so a commented example table can't masquerade as a real one.
 * Handles `--`, MySQL `#`, and block comments.
 * @param {string} sql
 * @returns {string}
 */
export function stripComments(sql) {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^#])#[^\n]*/gm, '$1')
    .replace(/(^|\s)--[^\n]*/gm, '$1');
}

/**
 * Index of the `)` that closes the `(` at `openIndex`, or -1. Skips single- and
 * double-quoted strings (and their doubled-quote escapes).
 * @param {string} sql
 * @param {number} openIndex
 * @returns {number}
 */
function matchParen(sql, openIndex) {
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  for (let i = openIndex; i < sql.length; i++) {
    const char = sql[i];
    if (inSingle) {
      if (char === "'") {
        if (sql[i + 1] === "'") i++;
        else inSingle = false;
      }
      continue;
    }
    if (inDouble) {
      if (char === '"') {
        if (sql[i + 1] === '"') i++;
        else inDouble = false;
      }
      continue;
    }
    if (char === "'") { inSingle = true; continue; }
    if (char === '"') { inDouble = true; continue; }
    if (char === '(') depth++;
    else if (char === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * Split a table body on top-level commas (tracking paren depth and quotes), so
 * `DECIMAL(10,2)` and `ENUM('a','b')` stay whole.
 * @param {string} body
 * @returns {string[]}
 */
function splitTopLevel(body) {
  /** @type {string[]} */
  const parts = [];
  let depth = 0;
  let start = 0;
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < body.length; i++) {
    const char = body[i];
    if (inSingle) {
      if (char === "'") {
        if (body[i + 1] === "'") i++;
        else inSingle = false;
      }
      continue;
    }
    if (inDouble) {
      if (char === '"') {
        if (body[i + 1] === '"') i++;
        else inDouble = false;
      }
      continue;
    }
    if (char === "'") { inSingle = true; continue; }
    if (char === '"') { inDouble = true; continue; }
    if (char === '(') depth++;
    else if (char === ')') depth--;
    else if (char === ',' && depth === 0) {
      parts.push(body.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(body.slice(start));
  return parts.map((part) => part.trim()).filter(Boolean);
}

/** @param {string} name @returns {string} */
export const unquote = (name) => name.replace(/^["`]/, '').replace(/["`]$/, '');

/** @param {string} raw @returns {string[]} */
const splitIds = (raw) => splitTopLevel(raw).map(unquote);

/**
 * Parse migration files into a tenant descriptor, or null when no tenant
 * aggregate root can be identified.
 *
 * @param {Array<{ name?: string, content: string }>} files — migration files
 *   (order-independent; relations are accumulated across all of them).
 * @returns {TenantDescriptor | null}
 */
export function parseSqlMigrations(files) {
  /** @type {Map<string, Array<{ target: string, localCols: string[] }>>} table → outgoing FKs */
  const outgoing = new Map();
  /** @type {Map<string, Set<string>>} table → tables referencing it */
  const incoming = new Map();
  /** @type {Set<string>} every table seen (for leaf tables with no FKs). */
  const allTables = new Set();

  for (const file of files) {
    const sql = stripComments(file.content ?? '');
    const createRe = new RegExp(CREATE_TABLE_RE.source, 'gi');
    let match;
    while ((match = createRe.exec(sql))) {
      // Group 2 is the table for `CREATE TABLE schema.table`; group 1 for the
      // unqualified form `CREATE TABLE table`.
      const table = unquote(match[2] ?? match[1]);
      const open = createRe.lastIndex - 1; // index of the opening `(`
      const close = matchParen(sql, open);
      if (close === -1) continue;
      const body = sql.slice(open + 1, close);
      allTables.add(table);

      /** @type {Array<{ target: string, localCols: string[] }>} */
      const relations = [];
      for (const part of splitTopLevel(body)) {
        const tableFk = TABLE_FK_RE.exec(part);
        if (tableFk) {
          relations.push({ target: unquote(tableFk[3]), localCols: splitIds(tableFk[1]) });
          continue;
        }
        const inline = INLINE_REF_RE.exec(part);
        if (inline) {
          const column = LEADING_COLUMN_RE.exec(part)?.[1];
          if (column) relations.push({ target: unquote(inline[2]), localCols: [unquote(column)] });
        }
      }
      outgoing.set(table, relations);
      for (const relation of relations) {
        if (!incoming.has(relation.target)) incoming.set(relation.target, new Set());
        incoming.get(relation.target)?.add(table);
      }
      createRe.lastIndex = close + 1;
    }
  }

  // The tenant is the aggregate root: referenced by ≥2 tables, referencing none.
  const candidates = [...incoming.entries()]
    .filter(([table, refs]) => refs.size >= 2 && (outgoing.get(table)?.length ?? 0) === 0)
    .sort((a, b) => b[1].size - a[1].size);

  if (candidates.length === 0) return null;
  // Two tables tied for the highest in-degree — refuse to guess.
  if (candidates.length > 1 && candidates[0][1].size === candidates[1][1].size) return null;

  const [tenantEntity] = candidates[0];
  /** @type {Set<string>} */
  const scopeColumns = new Set();
  /** @type {Set<string>} */
  const scopedEntities = new Set();
  for (const [table, relations] of outgoing) {
    for (const relation of relations) {
      if (relation.target === tenantEntity) {
        scopedEntities.add(table);
        for (const col of relation.localCols) scopeColumns.add(col);
      }
    }
  }

  const globalEntities = new Set([...outgoing.keys()].filter((table) => table !== tenantEntity && !scopedEntities.has(table)));
  for (const table of allTables) {
    if (table !== tenantEntity && !scopedEntities.has(table) && !outgoing.has(table)) globalEntities.add(table);
  }

  return makeDescriptor({
    tenantEntity,
    scopeColumns: [...scopeColumns],
    scopedEntities: [...scopedEntities],
    globalEntities: [...globalEntities],
  });
}
