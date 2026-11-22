// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for tenant discovery — the Prisma parser and the dispatch.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parsePrismaSchema } from '../src/tenant/parsers/prisma.mjs';
import { parseSqlMigrations } from '../src/tenant/parsers/sql.mjs';
import { discoverTenant, guidanceFor } from '../src/tenant/discover.mjs';
import { makeDescriptor } from '../src/tenant/descriptor.mjs';

test('parsePrismaSchema identifies the tenant aggregate root (clientId)', () => {
  const descriptor = parsePrismaSchema(`
model Client {
  id String @id
  apiKeys ApiKey[]
  dashboardUsers DashboardUser[]
  requestLogs RequestLog[]
}
model ApiKey {
  id String @id
  clientId String
  client Client @relation(fields: [clientId], references: [id])
}
model DashboardUser {
  id String @id
  clientId String?
  client Client? @relation(fields: [clientId], references: [id])
}
model RequestLog {
  id String @id
  clientId String?
  client Client? @relation(fields: [clientId], references: [id])
}
model NewsArticle {
  id String @id
  title String
}
`);
  assert.ok(descriptor, 'expected a tenant descriptor');
  assert.equal(descriptor?.tenantEntity, 'Client');
  assert.deepEqual([...(descriptor?.scopeColumns ?? [])].sort(), ['clientId']);
  assert.deepEqual([...(descriptor?.scopedEntities ?? [])].sort(), ['ApiKey', 'DashboardUser', 'RequestLog']);
  assert.deepEqual(descriptor?.globalEntities, ['NewsArticle']);
});

test('parsePrismaSchema returns null without an aggregate root (single reference)', () => {
  const descriptor = parsePrismaSchema(`
model Client { id String @id }
model Widget { id String @id clientId String client Client @relation(fields: [clientId], references: [id]) }
`);
  assert.equal(descriptor, null);
});

test('parsePrismaSchema returns null when two roots are tied (ambiguous)', () => {
  const descriptor = parsePrismaSchema(`
model A { id String @id x X[] y Y[] }
model B { id String @id x X[] y Y[] }
model X {
  id String @id
  aId String
  a A @relation(fields: [aId], references: [id])
  bId String
  b B @relation(fields: [bId], references: [id])
}
model Y {
  id String @id
  aId String
  a A @relation(fields: [aId], references: [id])
  bId String
  b B @relation(fields: [bId], references: [id])
}
`);
  assert.equal(descriptor, null);
});

test('parsePrismaSchema ignores commented-out models', () => {
  const descriptor = parsePrismaSchema(`
// model Ghost { id String @id }
model Client { id String @id }
model Widget { id String @id clientId String client Client @relation(fields: [clientId], references: [id]) }
model Thing { id String @id clientId String client Client @relation(fields: [clientId], references: [id]) }
`);
  assert.equal(descriptor?.tenantEntity, 'Client');
});

test('makeDescriptor drops invalid identifiers', () => {
  const descriptor = makeDescriptor({
    tenantEntity: 'Client',
    scopeColumns: ['clientId', 'bad value', 'ok_id'],
  });
  assert.deepEqual(descriptor?.scopeColumns, ['clientId', 'ok_id']);
  assert.equal(makeDescriptor({ tenantEntity: 'bad name', scopeColumns: ['x'] }), null);
});

test('discoverTenant reports no-parseable-data-layer without a data layer', () => {
  const result = discoverTenant(
    /** @type {any} */ ({ repoRoot: '/tmp/x', targets: ['/tmp/x/src'], stack: {} }),
  );
  assert.deepEqual(result, { notVerifiable: 'no-parseable-data-layer' });
  assert.ok(guidanceFor('no-parseable-data-layer').length > 0);
});

/** Create a temp dir with one `.sql` migration, returning its path.
 * @param {string} ddl */
function sqlFixture(ddl) {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-sql-'));
  writeFileSync(join(dir, '001_init.sql'), ddl, 'utf8');
  return dir;
}

test('discoverTenant discovers the tenant from SQL migrations (dataLayer: sql)', () => {
  const dir = sqlFixture(`
CREATE TABLE clients (id BIGINT PRIMARY KEY);
CREATE TABLE api_keys (
  id BIGINT PRIMARY KEY,
  client_id BIGINT REFERENCES clients(id)
);
CREATE TABLE request_logs (
  id BIGINT PRIMARY KEY,
  client_id BIGINT REFERENCES clients(id)
);
`);
  try {
    const result = discoverTenant(
      /** @type {any} */ ({ repoRoot: dir, targets: [dir], stack: { sql: true } }),
    );
    assert.equal(result.dataLayer, 'sql');
    assert.equal(result.descriptor?.tenantEntity, 'clients');
    assert.deepEqual([...(result.descriptor?.scopeColumns ?? [])].sort(), ['client_id']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('discoverTenant reports sql-no-tenant-entity when no aggregate root', () => {
  const dir = sqlFixture(`
CREATE TABLE clients (id BIGINT PRIMARY KEY);
CREATE TABLE widgets (
  id BIGINT PRIMARY KEY,
  client_id BIGINT REFERENCES clients(id)
);
`);
  try {
    const result = discoverTenant(
      /** @type {any} */ ({ repoRoot: dir, targets: [dir], stack: { sql: true } }),
    );
    assert.equal(result.notVerifiable, 'sql-no-tenant-entity');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('parseSqlMigrations uses the table name for schema-qualified CREATE TABLE', () => {
  const descriptor = parseSqlMigrations([
    {
      name: '001.sql',
      content: `
CREATE TABLE public.clients (id BIGINT PRIMARY KEY);
CREATE TABLE api_keys (id BIGINT PRIMARY KEY, client_id BIGINT REFERENCES clients(id));
CREATE TABLE request_logs (id BIGINT PRIMARY KEY, client_id BIGINT REFERENCES clients(id));
`,
    },
  ]);
  assert.equal(descriptor?.tenantEntity, 'clients');
  assert.deepEqual([...(descriptor?.scopeColumns ?? [])].sort(), ['client_id']);
});

test('guidanceFor names the discovered SQL tenant', () => {
  assert.ok(guidanceFor('sql-not-checkable', 'clients').includes('clients'));
});
