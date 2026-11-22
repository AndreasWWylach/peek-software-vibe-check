// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for the PostgreSQL/Supabase row-level-security provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeRls, detectPostgresApp, rlsProvider } from '../src/providers/rls.mjs';

/** @param {string} content @param {string} [name] */
function file(content, name = '001_init.sql') {
  return { name, content };
}

test('analyzeRls flags tables without RLS and clears those with ENABLE', () => {
  const tables = analyzeRls([
    file(`
CREATE TABLE clients (id BIGINT PRIMARY KEY);
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
CREATE TABLE orders (id BIGINT PRIMARY KEY);
`),
  ]);
  const byName = Object.fromEntries(tables.map((t) => [t.table, t]));
  assert.equal(byName.clients.rlsOn, true);
  assert.equal(byName.orders.rlsOn, false);
  assert.equal(byName.orders.policies, 0);
  assert.equal(byName.orders.line, 4);
});

test('analyzeRls: last state change wins (DISABLE after ENABLE)', () => {
  const tables = analyzeRls([
    file(`
CREATE TABLE clients (id BIGINT PRIMARY KEY);
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients DISABLE ROW LEVEL SECURITY;
`),
  ]);
  assert.equal(tables[0].rlsOn, false);
});

test('analyzeRls: FORCE counts as enabled', () => {
  const tables = analyzeRls([
    file(`
CREATE TABLE clients (id BIGINT PRIMARY KEY);
ALTER TABLE clients FORCE ROW LEVEL SECURITY;
`),
  ]);
  assert.equal(tables[0].rlsOn, true);
});

test('analyzeRls: schema-qualified CREATE TABLE and ALTER TABLE', () => {
  const tables = analyzeRls([
    file(`
CREATE TABLE public.orders (id BIGINT PRIMARY KEY);
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
CREATE TABLE public.audit (id BIGINT PRIMARY KEY);
`),
  ]);
  const byName = Object.fromEntries(tables.map((t) => [t.table, t]));
  assert.equal(byName.orders.rlsOn, true);
  assert.equal(byName.audit.rlsOn, false);
});

test('analyzeRls: counts policies and ignores them without ENABLE', () => {
  const tables = analyzeRls([
    file(`
CREATE TABLE posts (id BIGINT PRIMARY KEY);
CREATE POLICY "tenant read access" ON posts USING (tenant_id = 1);
CREATE POLICY "admin full access" ON posts USING (role = 'admin');
`),
  ]);
  assert.equal(tables[0].rlsOn, false);
  assert.equal(tables[0].policies, 2);
});

test('analyzeRls: commented-out statements are ignored', () => {
  const tables = analyzeRls([
    file(`
CREATE TABLE clients (id BIGINT PRIMARY KEY);
-- ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
/* CREATE POLICY x ON clients USING (true); */
`),
  ]);
  assert.equal(tables[0].rlsOn, false);
  assert.equal(tables[0].policies, 0);
});

test('detectPostgresApp: stack markers win', () => {
  assert.equal(detectPostgresApp({ supabase: true }, []), true);
  assert.equal(detectPostgresApp({ postgres: true }, []), true);
});

test('detectPostgresApp: Postgres-only DDL in the migrations', () => {
  for (const ddl of [
    'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";',
    'CREATE POLICY p ON t USING (true);',
    'ALTER TABLE t ENABLE ROW LEVEL SECURITY;',
    "CREATE TYPE status AS ENUM ('new', 'done');",
    "SELECT data::jsonb FROM t;",
  ]) {
    assert.equal(detectPostgresApp({}, [file(ddl)]), true, `expected Postgres signal: ${ddl}`);
  }
});

test('detectPostgresApp: MySQL-only DDL is not Postgres', () => {
  assert.equal(
    detectPostgresApp({}, [
      file(`
CREATE TABLE clients (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(191) NOT NULL
) ENGINE=InnoDB;
`),
    ]),
    false,
  );
  assert.equal(detectPostgresApp({}, []), false);
});

/** Build a temp repo with one migration and run the provider against it.
 * @param {string} ddl
 * @param {Record<string, boolean>} stack
 * @returns {Promise<import('../src/types.mjs').Finding[]>}
 */
async function runProvider(ddl, stack) {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-rls-'));
  writeFileSync(join(dir, '001_init.sql'), ddl, 'utf8');
  try {
    return await rlsProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: dir, targets: [dir], stack, log: () => {} }),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('rlsProvider: unprotected table in a Supabase app is a critical finding', async () => {
  const findings = await runProvider(
    `
CREATE TABLE clients (id BIGINT PRIMARY KEY);
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
CREATE TABLE orders (id BIGINT PRIMARY KEY);
`,
    { sql: true, supabase: true },
  );
  assert.equal(findings.length, 1);
  const [finding] = findings;
  assert.equal(finding.file, '001_init.sql');
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.teardownId, 'TD-008');
  assert.equal(finding.pillar, 'security');
  assert.match(finding.title, /orders/);
  assert.match(finding.fixSummary ?? '', /ENABLE ROW LEVEL SECURITY/);
  assert.equal(finding.line, 4);
});

test('rlsProvider: policies without ENABLE is critical even without the client SDK', async () => {
  const findings = await runProvider(
    `
CREATE TABLE posts (id BIGINT PRIMARY KEY);
CREATE POLICY "tenant read access" ON posts USING (true);
`,
    { sql: true },
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  assert.match(findings[0].message ?? '', /never runs/);
});

test('rlsProvider: no client SDK and no policies is high, not critical', async () => {
  const findings = await runProvider(
    `
CREATE TABLE logs (id BIGINT PRIMARY KEY);
`,
    { sql: true, postgres: true },
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'high');
});

test('rlsProvider: a MySQL repo yields no findings', async () => {
  const findings = await runProvider(
    `
CREATE TABLE clients (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY) ENGINE=InnoDB;
`,
    { sql: true },
  );
  assert.deepEqual(findings, []);
});

test('rlsProvider: no SQL marker yields no findings', async () => {
  const findings = await runProvider('', { supabase: true });
  assert.deepEqual(findings, []);
});
