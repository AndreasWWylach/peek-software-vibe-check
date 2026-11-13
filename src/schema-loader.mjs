// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Reusable JSON Schema loader + validator (ajv).
 *
 * Shared by config validation and the report self-check so the same strict
 * rules apply everywhere. ajv is the engine's single runtime dependency.
 */
import { readFile } from 'node:fs/promises';
import { Ajv } from 'ajv';

/**
 * Read + parse a JSON Schema file from disk.
 * @param {string} schemaPath — absolute path to a `.schema.json` file.
 * @returns {Promise<object>} the parsed schema document.
 */
export async function loadSchema(schemaPath) {
  const raw = await readFile(schemaPath, 'utf8');
  return JSON.parse(raw);
}

/**
 * Create a strict Ajv instance (draft-07, all errors, unknown keywords fail).
 * @returns {Ajv} a configured validator factory.
 */
export function createValidator() {
  return new Ajv({ allErrors: true, strict: true });
}

/**
 * Validate `data` against `schema`, returning human-readable errors ([] when valid).
 * @param {Ajv} ajv — a validator from `createValidator`.
 * @param {object} schema — the schema document.
 * @param {unknown} data — the value to validate.
 * @returns {string[]} error messages; empty when the data is valid.
 */
export function validate(ajv, schema, data) {
  const check = ajv.compile(schema);
  const valid = check(data);
  if (valid) return [];
  const errors = /** @type {Array<{ instancePath?: string; message?: string; params?: Record<string, unknown> }>} */ (
    check.errors ?? []
  );
  return errors.map((err) => {
    const path = err.instancePath || '/';
    const params = err.params && Object.keys(err.params).length > 0 ? ` ${JSON.stringify(err.params)}` : '';
    return `${path} ${err.message || 'invalid'}${params}`;
  });
}
