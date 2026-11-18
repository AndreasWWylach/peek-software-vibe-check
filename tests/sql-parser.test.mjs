// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for the SQL-migrations tenant-discovery parser.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSqlMigrations } from '../src/tenant/parsers/sql.mjs';

/** @param {string} content @returns {{ name: string, content: string }} */
const migration = (content) => ({ name: '001_init.sql', content });

test('parseSqlMigrations identifies the tenant aggregate root from table-level FKs', () => {
  const descriptor = parseSqlMigrations([
    migration(`
CREATE TABLE clients (
  id BIGINT PRIMARY KEY,
  name VARCHAR(255) NOT NULL
);
CREATE TABLE api_keys (
  id BIGINT PRIMARY KEY,
  client_id BIGINT NOT NULL,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
CREATE TABLE dashboard_users (
  id BIGINT PRIMARY KEY,
  client_id BIGINT,
  CONSTRAINT fk_users_client FOREIGN KEY (client_id) REFERENCES clients(id)
);
CREATE TABLE news_articles (
  id BIGINT PRIMARY KEY,
  title VARCHAR(255)
);
`),
  ]);
  assert.ok(descriptor, 'expected a tenant descriptor');
  assert.equal(descriptor?.tenantEntity, 'clients');
  assert.deepEqual([...(descriptor?.scopeColumns ?? [])].sort(), ['client_id']);
  assert.deepEqual([...(descriptor?.scopedEntities ?? [])].sort(), ['api_keys', 'dashboard_users']);
  assert.deepEqual(descriptor?.globalEntities, ['news_articles']);
});

test('parseSqlMigrations reads column-level inline REFERENCES', () => {
  const descriptor = parseSqlMigrations([
    migration(`
CREATE TABLE clients (id BIGINT PRIMARY KEY);
CREATE TABLE api_keys (
  id BIGINT PRIMARY KEY,
  client_id BIGINT REFERENCES clients(id)
);
CREATE TABLE request_logs (
  id BIGINT PRIMARY KEY,
  client_id BIGINT REFERENCES clients(id)
);
`),
  ]);
  assert.ok(descriptor, 'expected a tenant descriptor');
  assert.equal(descriptor?.tenantEntity, 'clients');
  assert.deepEqual([...(descriptor?.scopeColumns ?? [])].sort(), ['client_id']);
  assert.deepEqual([...(descriptor?.scopedEntities ?? [])].sort(), ['api_keys', 'request_logs']);
});

test('parseSqlMigrations returns null without an aggregate root (single reference)', () => {
  const descriptor = parseSqlMigrations([
    migration(`
CREATE TABLE clients (id BIGINT PRIMARY KEY);
CREATE TABLE widgets (
  id BIGINT PRIMARY KEY,
  client_id BIGINT REFERENCES clients(id)
);
`),
  ]);
  assert.equal(descriptor, null);
});

test('parseSqlMigrations returns null when two roots are tied (ambiguous)', () => {
  const descriptor = parseSqlMigrations([
    migration(`
CREATE TABLE a (id BIGINT PRIMARY KEY);
CREATE TABLE b (id BIGINT PRIMARY KEY);
CREATE TABLE x (
  id BIGINT PRIMARY KEY,
  a_id BIGINT REFERENCES a(id),
  b_id BIGINT REFERENCES b(id)
);
CREATE TABLE y (
  id BIGINT PRIMARY KEY,
  a_id BIGINT REFERENCES a(id),
  b_id BIGINT REFERENCES b(id)
);
`),
  ]);
  assert.equal(descriptor, null);
});

test('parseSqlMigrations ignores commented-out tables and accumulates across files', () => {
  const descriptor = parseSqlMigrations([
    migration(`
-- CREATE TABLE ghost (id BIGINT PRIMARY KEY);
CREATE TABLE clients (id BIGINT PRIMARY KEY);
`),
    migration(`
CREATE TABLE api_keys (
  id BIGINT PRIMARY KEY,
  client_id BIGINT REFERENCES clients(id)
);
`),
    migration(`
CREATE TABLE request_logs (
  id BIGINT PRIMARY KEY,
  client_id BIGINT REFERENCES clients(id)
);
`),
  ]);
  assert.ok(descriptor, 'expected a tenant descriptor');
  assert.equal(descriptor?.tenantEntity, 'clients');
});

test('parseSqlMigrations tolerates DECIMAL/ENUM commas and quoted identifiers', () => {
  const descriptor = parseSqlMigrations([
    migration(`
CREATE TABLE "clients" (id BIGINT PRIMARY KEY);
CREATE TABLE "invoices" (
  id BIGINT PRIMARY KEY,
  amount DECIMAL(10, 2) NOT NULL,
  status ENUM('draft', 'sent', 'paid') NOT NULL,
  "client_id" BIGINT REFERENCES "clients"(id)
);
CREATE TABLE "payments" (
  id BIGINT PRIMARY KEY,
  "client_id" BIGINT REFERENCES "clients"(id)
);
`),
  ]);
  assert.ok(descriptor, 'expected a tenant descriptor');
  assert.equal(descriptor?.tenantEntity, 'clients');
  assert.deepEqual([...(descriptor?.scopeColumns ?? [])].sort(), ['client_id']);
  assert.deepEqual([...(descriptor?.scopedEntities ?? [])].sort(), ['invoices', 'payments']);
});
