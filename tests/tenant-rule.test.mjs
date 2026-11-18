// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for TD-008 tenant-column rule materialization (v2 ruleParams).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildTenantRuleYaml,
  materializeTenantRule,
  readTenantColumn,
  TENANT_COLUMN_RE,
} from '../src/providers/tenant-rule.mjs';
import { commandAvailable, runCommand } from '../src/proc.mjs';

test('TENANT_COLUMN_RE accepts identifiers and rejects injection attempts', () => {
  assert.ok(TENANT_COLUMN_RE.test('organizationId'));
  assert.ok(TENANT_COLUMN_RE.test('tenant_id'));
  assert.ok(TENANT_COLUMN_RE.test('_custom'));
  assert.ok(!TENANT_COLUMN_RE.test('org id'));
  assert.ok(!TENANT_COLUMN_RE.test('org}'));
  assert.ok(!TENANT_COLUMN_RE.test('org\nid'));
  assert.ok(!TENANT_COLUMN_RE.test("' OR 1=1 --"));
});

test('readTenantColumn validates the config value', () => {
  assert.equal(readTenantColumn({ ruleParams: { tenantColumn: 'organizationId' } }), 'organizationId');
  assert.equal(readTenantColumn({ ruleParams: { tenantColumn: '  accountId ' } }), 'accountId');
  assert.equal(readTenantColumn({ ruleParams: { tenantColumn: 'bad value' } }), null);
  assert.equal(readTenantColumn({ ruleParams: {} }), null);
  assert.equal(readTenantColumn({ ruleParams: undefined }), null);
});

test('buildTenantRuleYaml pins the configured column and its compound form', () => {
  const yaml = buildTenantRuleYaml('organizationId');
  assert.ok(yaml.includes('organizationId'));
  assert.ok(yaml.includes('id_organizationId'));
  assert.ok(yaml.includes('teardownId: TD-008'));
  assert.ok(yaml.includes('findUnique'));
  assert.ok(yaml.includes('deleteMany'));
  // The generic fallback columns must NOT leak into the parameterized rule.
  assert.ok(!yaml.includes('tenantId'));
  assert.ok(!yaml.includes('userId'));
});

test('buildTenantRuleYaml accepts multiple columns (auto-detected set)', () => {
  const yaml = buildTenantRuleYaml(['organizationId', 'workspaceId']);
  assert.ok(yaml.includes('organizationId'));
  assert.ok(yaml.includes('workspaceId'));
  assert.ok(yaml.includes('id_organizationId'));
  assert.ok(yaml.includes('id_workspaceId'));
  assert.ok(yaml.includes('expected one of: organizationId, workspaceId'));
  // The multi-column message lists columns after a colon — it must be quoted so
  // the generated YAML stays valid (a bare `:` would parse as a mapping).
  assert.ok(
    yaml.includes('message: "Prisma data query lacks tenant scope (expected one of:'),
    'multi-column message must be YAML-quoted',
  );
});

test('buildTenantRuleYaml enumerates scoped entities explicitly (global models excluded)', () => {
  const yaml = buildTenantRuleYaml('clientId', ['ApiKey', 'RequestLog']);
  // Prisma accessors are lowercase-first (RequestLog → requestLog).
  assert.ok(yaml.includes("'$PRISMA.requestLog.findUnique"));
  assert.ok(yaml.includes("'$PRISMA.apiKey.findUnique"));
  assert.ok(yaml.includes("pattern-not: '$PRISMA.requestLog.$METHOD"));
  // No generic $MODEL in scoped mode — global models can never match.
  assert.ok(!yaml.includes('$PRISMA.$MODEL'));
  // Unknown scope → generic $MODEL fallback.
  const open = buildTenantRuleYaml('clientId');
  assert.ok(open.includes('$PRISMA.$MODEL.findUnique'));
});

test('materializeTenantRule writes a readable rule file and returns its path', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-rule-test-'));
  try {
    const file = materializeTenantRule('organizationId', null, dir);
    assert.ok(existsSync(file));
    assert.ok(readFileSync(file, 'utf8').includes('organizationId'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const semgrepAvailable = commandAvailable('semgrep');

test(
  'materialized tenant rule fires on unscoped queries and stays silent on scoped ones',
  { skip: semgrepAvailable ? false : 'semgrep not installed — tenant-rule test skipped' },
  () => {
    // Write the materialized rule INSIDE the repo so the local Docker semgrep
    // wrapper (which mounts only the engine repo) can reach it. Native semgrep
    // (CI + real machines) reads it identically.
    const repoRulesTmp = fileURLToPath(new URL('./.tmp-tenant-rule', import.meta.url));
    const rule = materializeTenantRule('organizationId', null, repoRulesTmp);
    const fixturesDir = fileURLToPath(new URL('./golden/fixtures/td-008', import.meta.url));

    try {
      const files = [
        join(fixturesDir, 'td-008.vulnerable.ts'),
        join(fixturesDir, 'td-008.vulnerable.findmany.ts'),
        join(fixturesDir, 'td-008.hardened.ts'),
        join(fixturesDir, 'td-008.hardened.findmany.ts'),
      ];
      const stdout = runCommand('semgrep', ['--config', rule, '--json', ...files]);
      const results = /** @type {Array<Record<string, any>>} */ (
        Array.isArray(JSON.parse(stdout).results) ? JSON.parse(stdout).results : []
      );
      /** @param {string} name @returns {number} */
      const count = (name) => results.filter((result) => String(result.path ?? '').endsWith(name)).length;

      assert.ok(count('td-008.vulnerable.ts') > 0, 'unscoped update must fire');
      assert.ok(count('td-008.vulnerable.findmany.ts') > 0, 'unscoped findMany must fire');
      assert.equal(count('td-008.hardened.ts'), 0, 'scoped update must stay silent');
      assert.equal(count('td-008.hardened.findmany.ts'), 0, 'scoped findMany must stay silent');
    } finally {
      rmSync(repoRulesTmp, { recursive: true, force: true });
    }
  },
);

test(
  'multi-column tenant rule is valid YAML that semgrep accepts',
  { skip: semgrepAvailable ? false : 'semgrep not installed — tenant-rule test skipped' },
  () => {
    // Regression for a colon in the unquoted multi-column message producing
    // "Invalid YAML … mapping values are not allowed here".
    const repoRulesTmp = fileURLToPath(new URL('./.tmp-tenant-rule-multi', import.meta.url));
    const rule = materializeTenantRule(['organizationId', 'workspaceId'], null, repoRulesTmp);
    const fixturesDir = fileURLToPath(new URL('./golden/fixtures/td-008', import.meta.url));
    try {
      const stdout = runCommand('semgrep', [
        '--config', rule, '--json',
        join(fixturesDir, 'td-008.vulnerable.ts'),
      ]);
      const parsed = JSON.parse(stdout);
      assert.ok(Array.isArray(parsed.results), 'semgrep must parse the rule and return results');
    } finally {
      rmSync(repoRulesTmp, { recursive: true, force: true });
    }
  },
);

test(
  'tenant rule restricted to scoped models ignores global entities',
  { skip: semgrepAvailable ? false : 'semgrep not installed — tenant-rule test skipped' },
  () => {
    const repoRulesTmp = fileURLToPath(new URL('./.tmp-tenant-rule-scoped', import.meta.url));
    const rule = materializeTenantRule('clientId', ['ApiKey', 'RequestLog'], repoRulesTmp);
    const fixturesDir = fileURLToPath(new URL('./fixtures/tenant-scoped', import.meta.url));
    try {
      const stdout = runCommand('semgrep', [
        '--config', rule, '--json',
        join(fixturesDir, 'scoped.vulnerable.ts'),
        join(fixturesDir, 'scoped.hardened.ts'),
        join(fixturesDir, 'global.ts'),
      ]);
      const results = /** @type {Array<Record<string, any>>} */ (
        Array.isArray(JSON.parse(stdout).results) ? JSON.parse(stdout).results : []
      );
      /** @param {string} name @returns {number} */
      const count = (name) => results.filter((result) => String(result.path ?? '').endsWith(name)).length;
      assert.ok(count('scoped.vulnerable.ts') > 0, 'unscoped scoped-model query must fire');
      assert.equal(count('scoped.hardened.ts'), 0, 'scoped scoped-model query must stay silent');
      assert.equal(count('global.ts'), 0, 'a global model query must never fire');
    } finally {
      rmSync(repoRulesTmp, { recursive: true, force: true });
    }
  },
);
