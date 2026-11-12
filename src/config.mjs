// @ts-check
/**
 * @fileoverview Scan-config loader — reads, schema-validates, and normalizes
 * `peek-config.json`.
 *
 * The config is inert, declarative data (never code). It is validated against
 * the published JSON Schema and the engine-version range is enforced before
 * anything runs — malformed or incompatible config fails loudly.
 */
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createValidator, loadSchema, validate } from './schema-loader.mjs';
import { ENGINE_NAME, ENGINE_VERSION, satisfiesEngineRange } from './version.mjs';

/** @typedef {import('./types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('./types.mjs').Pillar} Pillar */

/** Absolute path to the bundled config schema. */
const CONFIG_SCHEMA_PATH = fileURLToPath(new URL('../schema/peek-config.schema.json', import.meta.url));

/** v1 pillar weights — every pillar contributes equally. */
const DEFAULT_WEIGHTS = /** @type {Record<Pillar, number>} */ ({ security: 1, runtime: 1, architecture: 1, qa: 1 });

/**
 * Load and validate a scan config from disk.
 * @param {string} configPath — absolute path to `peek-config.json`.
 * @returns {Promise<ScanConfig>} the validated config (typed, defaults applied).
 * @throws {Error} if the file is missing, invalid JSON, fails schema validation, or requires a newer engine.
 */
export async function loadConfig(configPath) {
  let raw;
  try {
    raw = await readFile(configPath, 'utf8');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Cannot read config at ${configPath}: ${message}`);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Config at ${configPath} is not valid JSON: ${message}`);
  }

  const errors = validate(createValidator(), await loadSchema(CONFIG_SCHEMA_PATH), data);
  if (errors.length > 0) {
    throw new Error(`Invalid peek-config.json (${configPath}):\n  - ${errors.join('\n  - ')}`);
  }

  // Normalize optional fields — ajv validates structure but does not apply
  // `default` values, so fill them in here to guarantee a complete config.
  const weights = { ...DEFAULT_WEIGHTS, ...(data.scoring?.weights ?? {}) };
  const config = /** @type {ScanConfig} */ ({
    ...data,
    languages: data.languages ?? [],
    enabledRules: data.enabledRules ?? [],
    ruleParams: data.ruleParams ?? {},
    scoring: { weights },
  });

  if (!satisfiesEngineRange(config.engine, ENGINE_VERSION)) {
    throw new Error(
      `${ENGINE_NAME} ${ENGINE_VERSION} does not satisfy the config's engine requirement "${config.engine}". ` +
        'Update the engine or regenerate the config.',
    );
  }

  return config;
}
