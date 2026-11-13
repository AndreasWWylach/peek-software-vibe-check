// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for config schema validation.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createValidator, loadSchema, validate } from '../src/schema-loader.mjs';

/** Absolute path to the bundled config schema. */
const CONFIG_SCHEMA_PATH = fileURLToPath(new URL('../schema/peek-config.schema.json', import.meta.url));

test('a minimal valid config passes', async () => {
  const schema = await loadSchema(CONFIG_SCHEMA_PATH);
  const config = { version: 1, engine: '>=0.1.0', targets: ['src/'], enabledRules: ['TD-008'] };
  assert.deepEqual(validate(createValidator(), schema, config), []);
});

test('a malformed config reports errors', async () => {
  const schema = await loadSchema(CONFIG_SCHEMA_PATH);
  const bad = { version: 1, engine: '>=0.1.0', targets: [], enabledRules: ['not-a-td'] };
  const errors = validate(createValidator(), schema, bad);
  assert.ok(errors.length > 0);
  assert.ok(errors.some((e) => e.includes('targets')));
  assert.ok(errors.some((e) => e.includes('enabledRules')));
});

test('unknown top-level keys are rejected (inert config, no surprises)', async () => {
  const schema = await loadSchema(CONFIG_SCHEMA_PATH);
  const config = { version: 1, engine: '>=0.1.0', targets: ['src/'], enabledRules: [], runThis: 'echo pwned' };
  const errors = validate(createValidator(), schema, config);
  assert.ok(errors.some((e) => e.includes('runThis')));
});
