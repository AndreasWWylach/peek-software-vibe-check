// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview PostgreSQL/Supabase row-level-security provider (TD-008, SQL
 * flavor).
 *
 * In a Postgres/Supabase app the table-level tenant/access boundary is RLS —
 * not an ORM `where` clause. This provider (pure Node, no binary) checks that
 * boundary in the SQL migrations:
 *
 *   1. Every `CREATE TABLE` must be followed by
 *      `ALTER TABLE … ENABLE ROW LEVEL SECURITY` (`FORCE` also counts).
 *   2. A table with `CREATE POLICY` statements but RLS never enabled is the
 *      silent killer: the policies read like protection but Postgres ignores
 *      them, so the table is fully open.
 *
 * Precision first: the check only fires when the repo proves it is a
 * Postgres/Supabase app — a `supabase`/`postgres` stack marker (SDK dependency
 * or `supabase/config.toml`) or Postgres-only DDL in the migrations. MySQL has
 * no RLS concept, so a MySQL-only repo can never trip it.
 */
import { readFileSync } from 'node:fs';
import { relative } from 'node:path';
import { collectFiles } from '../tenant/discover.mjs';
import { CREATE_TABLE_RE, stripComments, unquote } from '../tenant/parsers/sql.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').Finding} Finding */

/** The teardown this provider maps to (tenant/access boundary). */
const TEARDOWN_ID = 'TD-008';

/**
 * `ALTER TABLE [IF EXISTS] [ONLY] [schema.]table (ENABLE|DISABLE|FORCE|NO FORCE) ROW LEVEL SECURITY`
 * — captures schema (group 2, optional), table (group 2 or 1) and action (group 3).
 */
const ALTER_RLS_RE =
  /\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?("?[A-Za-z_][A-Za-z0-9_]*"?)(?:\s*\.\s*("?[A-Za-z_][A-Za-z0-9_]*"?))?\s+(ENABLE|DISABLE|FORCE|NO\s+FORCE)\s+ROW\s+LEVEL\s+SECURITY/gi;

/**
 * `CREATE POLICY [quoted name] ON [schema.]table` — captures schema (1, optional)
 * and table (2). The policy name is matched but not captured: Supabase's own
 * generated names are double-quoted and contain spaces (`"Enable read access"`).
 */
const CREATE_POLICY_RE =
  /\bCREATE\s+POLICY\s+(?:"(?:[^"]|"")*"|"?[A-Za-z_][A-Za-z0-9_]*"?)\s+ON\s+(?:"?([A-Za-z_][A-Za-z0-9_]*)"?\s*\.\s*)?("?[A-Za-z_][A-Za-z0-9_]*"?)\b/gi;

/**
 * Postgres-only DDL/token signals. Deliberately conservative — nothing here is
 * valid MySQL (MySQL has no `CREATE TYPE`, `CREATE EXTENSION`, policies, RLS,
 * `::jsonb` casts, or `SERIAL`/`TIMESTAMPTZ` types), so a MySQL migration can
 * never be misread as Postgres.
 */
const PG_ONLY_RE =
  /\bCREATE\s+EXTENSION\b|\bCREATE\s+TYPE\b|\bALTER\s+TYPE\b|\b(?:BIGSERIAL|SMALLSERIAL|TIMESTAMPTZ|TIMETZ)\b|::(?:jsonb|uuid)\b|\b(?:gen_random_uuid|uuid_generate_v4)\s*\(|\bCREATE\s+POLICY\b|\bROW\s+LEVEL\s+SECURITY\b/i;

/**
 * RLS state of one migrated table.
 * @typedef {Object} RlsTable
 * @property {string} table — table name (identifier-safe, from the DDL regex).
 * @property {string} file — repo-relative path of the migration with its `CREATE TABLE`.
 * @property {number | null} line — 1-based line of that `CREATE TABLE`.
 * @property {boolean} rlsOn — is RLS enabled after the last state change?
 * @property {number} policies — `CREATE POLICY` statements referencing the table.
 */

/**
 * Analyze migration files into per-table RLS state. Statement order matters:
 * `DISABLE` after `ENABLE` wins (last statement wins), matching how migrations
 * apply.
 *
 * @param {Array<{ name?: string, content: string }>} files — migration files
 *   (applied in the order given).
 * @returns {RlsTable[]}
 */
export function analyzeRls(files) {
  /** @type {Map<string, RlsTable>} */
  const tables = new Map();

  for (const file of files) {
    const sql = stripComments(file.content ?? '');

    const createRe = new RegExp(CREATE_TABLE_RE.source, 'gi');
    let match;
    while ((match = createRe.exec(sql))) {
      const table = unquote(match[2] ?? match[1]);
      if (!tables.has(table)) {
        tables.set(table, {
          table,
          file: file.name ?? '',
          line: lineAt(sql, match.index),
          rlsOn: false,
          policies: 0,
        });
      }
    }

    const alterRe = new RegExp(ALTER_RLS_RE.source, 'gi');
    while ((match = alterRe.exec(sql))) {
      const table = unquote(match[2] ?? match[1]);
      const entry = tables.get(table);
      if (!entry) continue; // altered here, created outside the collected files
      const action = (match[3] ?? '').toUpperCase().replace(/\s+/g, ' ');
      if (action === 'DISABLE') entry.rlsOn = false;
      else if (action !== 'NO FORCE') entry.rlsOn = true; // ENABLE or FORCE
    }

    const policyRe = new RegExp(CREATE_POLICY_RE.source, 'gi');
    while ((match = policyRe.exec(sql))) {
      const table = unquote(match[2] ?? match[1]);
      const entry = tables.get(table);
      if (entry) entry.policies += 1;
    }
  }

  return [...tables.values()];
}

/**
 * Is this repo a Postgres/Supabase app? Stack markers win; otherwise the
 * migrations must contain Postgres-only DDL.
 *
 * @param {Record<string, boolean> | undefined} stack
 * @param {Array<{ name?: string, content: string }>} files
 * @returns {boolean}
 */
export function detectPostgresApp(stack, files) {
  if (stack?.supabase || stack?.postgres) return true;
  for (const file of files) {
    if (PG_ONLY_RE.test(stripComments(file.content ?? ''))) return true;
  }
  return false;
}

/** @type {Provider} */
export const rlsProvider = {
  id: 'rls',
  name: 'PostgreSQL/Supabase (row-level security)',
  available: () => Promise.resolve(true),
  applicable: () => true,
  async run(_config, ctx) {
    const stack = ctx.stack ?? {};
    if (!stack.sql) return []; // no SQL migrations — nothing to check.

    const files = collectFiles(ctx, (name) => name.toLowerCase().endsWith('.sql')).map(
      (file) => ({
        name: relative(ctx.repoRoot, file).replace(/\\/g, '/'),
        content: readFileSync(file, 'utf8'),
      }),
    );
    if (files.length === 0) return [];
    if (!detectPostgresApp(stack, files)) return [];

    // `supabase` marker = the browser SDK is a dependency, so a direct client
    // path to the database exists — an RLS-less table is then fully reachable.
    const clientDirect = stack.supabase === true;
    return analyzeRls(files)
      .filter((table) => !table.rlsOn)
      .map((table) => unprotectedTableFinding(table, clientDirect));
  },
};

/**
 * Build the finding for a table whose RLS is off.
 * @param {RlsTable} table
 * @param {boolean} clientDirect — the Supabase JS SDK is in use (browser access).
 * @returns {Finding}
 */
function unprotectedTableFinding(table, clientDirect) {
  const hasPolicies = table.policies > 0;
  // A team that wrote policies but never ran ENABLE believes the table is
  // protected while it is fully open — the highest-risk state. Same for a
  // browser SDK pointed at the database with no server boundary in between.
  const severity = hasPolicies || clientDirect ? 'critical' : 'high';
  const policyWord = `${table.policies} \`CREATE POLICY\` statement${table.policies === 1 ? '' : 's'}`;

  const title = hasPolicies
    ? `RLS is never enabled on ${table.table} — ${policyWord} ${table.policies === 1 ? 'is' : 'are'} inert`
    : `No row-level security on ${table.table}`;

  const message = hasPolicies
    ? `${policyWord} ${table.policies === 1 ? 'references' : 'reference'} \`${table.table}\`, but \`ALTER TABLE ${table.table} ENABLE ROW LEVEL SECURITY\` never runs — Postgres ignores policies on RLS-disabled tables, so every row is readable and writable.`
    : clientDirect
      ? `The Supabase JS client is a dependency (browser access to the database), but \`${table.table}\` has row-level security disabled — the client SDK can read and write every row in it.`
      : `\`${table.table}\` never has row-level security enabled. Any query path that reaches it without an ownership filter lets any user read and write every row.`;

  const fixSummary = hasPolicies
    ? `Add a migration that runs \`ALTER TABLE ${table.table} ENABLE ROW LEVEL SECURITY;\` so the existing policies take effect.`
    : `Add a migration that enables RLS and adds a tenant-scoped policy, e.g. \`ALTER TABLE ${table.table} ENABLE ROW LEVEL SECURITY; CREATE POLICY tenant_access ON ${table.table} USING (tenant_id = current_setting('app.tenant_id')::uuid);\``;

  return {
    id: `rls:${table.file}:${table.table}`,
    kind: 'teardown',
    file: table.file,
    line: table.line,
    column: null,
    severity,
    pillar: 'security',
    teardownId: TEARDOWN_ID,
    title,
    message,
    fixSummary,
    source: { provider: 'rls', ruleId: hasPolicies ? 'policies-not-enabled' : 'missing-rls' },
    dependency: null,
  };
}

/**
 * 1-based line number of a character index.
 * @param {string} sql
 * @param {number} index
 * @returns {number}
 */
function lineAt(sql, index) {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (sql[i] === '\n') line += 1;
  }
  return line;
}
