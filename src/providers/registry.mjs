// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Provider registry — the pluggable analysis pipeline.
 *
 * Every analysis capability is a Provider emitting findings in the shared
 * `peek-report.json` shape. Two gates per provider (design doc §5.7):
 *   - `available()`  — binary installed? Missing → skipped, never a failure.
 *   - `applicable()` — does it fit this app's facets/languages?
 */
/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').SkipRecord} SkipRecord */

/**
 * Run every registered provider that is both installed and applicable.
 * @param {Provider[]} providers
 * @param {ScanConfig} config
 * @param {RunContext} ctx
 * @returns {Promise<{ findings: Finding[]; skipped: SkipRecord[] }>}
 */
export async function runProviders(providers, config, ctx) {
  /** @type {Finding[]} */
  const findings = [];
  /** @type {SkipRecord[]} */
  const skipped = [];

  for (const provider of providers) {
    ctx.log(`▸ ${provider.name} …`);

    if (!(await provider.available())) {
      skipped.push({
        id: provider.id,
        reason: 'not-installed',
        detail: `${provider.name} is not installed; install it to enable this check.`,
      });
      ctx.log('  skipped (not installed)');
      continue;
    }

    if (!provider.applicable(config)) {
      skipped.push({
        id: provider.id,
        reason: 'not-applicable',
        detail: `${provider.name} does not apply to this app.`,
      });
      ctx.log('  skipped (not applicable)');
      continue;
    }

    try {
      const found = await provider.run(config, ctx);
      findings.push(...found);
      ctx.log(`  ${found.length} finding(s)`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      skipped.push({ id: provider.id, reason: 'error', detail: message });
      ctx.log(`  error: ${message}`);
    }
  }

  return { findings, skipped };
}
