// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Golden test harness — every custom Semgrep rule must fire on its
 * TD's `vulnerableCode` and stay silent on its `hardenedCode` (docs §7.3).
 *
 * Skipped when `semgrep` is not on PATH: the harness is the credibility gate,
 * but the engine itself degrades gracefully without the binary. Install semgrep
 * (`pipx install semgrep` or `semgrep.dev`) to run these locally.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommand } from '../src/proc.mjs';

/** Absolute path to the custom rules root. */
const RULES_ROOT = fileURLToPath(new URL('../rules/peek', import.meta.url));
/** Absolute path to the golden fixtures root. */
const FIXTURES_ROOT = fileURLToPath(new URL('./golden/fixtures', import.meta.url));

const semgrepAvailable = commandAvailable('semgrep');
const skipReason = semgrepAvailable ? false : 'semgrep is not installed — golden tests skipped';

/**
 * Run semgrep once over a TD's fixture files and return a per-file finding count.
 * @param {string} ruleDir — `rules/peek/<TD-id>`.
 * @param {string[]} fixturePaths — absolute paths to the fixture files.
 * @returns {Map<string, number>} fixture basename → finding count.
 */
function scanFixtures(ruleDir, fixturePaths) {
  if (!existsSync(ruleDir)) {
    throw new Error(`No rule directory for golden fixtures: ${ruleDir}`);
  }
  const ruleFiles = readdirSync(ruleDir)
    .filter((file) => file.endsWith('.yaml'))
    .map((file) => join(ruleDir, file));
  if (ruleFiles.length === 0) {
    throw new Error(`No rule files in ${ruleDir}`);
  }

  /** @type {string[]} */
  const args = [];
  for (const file of ruleFiles) args.push('--config', file);
  args.push('--json', ...fixturePaths);

  const stdout = runCommand('semgrep', args);
  const parsed = JSON.parse(stdout);
  const results = /** @type {Array<Record<string, any>>} */ (Array.isArray(parsed.results) ? parsed.results : []);

  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const result of results) {
    const name = basename(String(result.path ?? ''));
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return counts;
}

for (const entry of readdirSync(FIXTURES_ROOT)) {
  const fixtureDir = join(FIXTURES_ROOT, entry);
  if (!statSync(fixtureDir).isDirectory()) continue;

  const tdId = entry.toUpperCase(); // td-002 → TD-002
  const ruleDir = join(RULES_ROOT, tdId);
  const fixtures = readdirSync(fixtureDir);
  const fixturePaths = fixtures.map((file) => join(fixtureDir, file));
  const counts = semgrepAvailable ? scanFixtures(ruleDir, fixturePaths) : new Map();

  for (const fixture of fixtures) {
    const mustFire = fixture.includes('.vulnerable.');
    const isHardened = fixture.includes('.hardened.');
    if (!mustFire && !isHardened) continue;

    const expectation = mustFire ? 'fires' : 'is silent';
    test(`golden: ${tdId} ${expectation} on ${fixture}`, { skip: skipReason }, () => {
      const count = counts.get(fixture) ?? 0;
      if (mustFire) {
        assert.ok(count > 0, `expected ${tdId} to fire on ${fixture}, got ${count} finding(s)`);
      } else {
        assert.equal(count, 0, `expected ${tdId} to be silent on ${fixture}, got ${count} finding(s)`);
      }
    });
  }
}

test('every shipped rule has vulnerable + hardened golden fixtures', () => {
  for (const entry of readdirSync(RULES_ROOT)) {
    const ruleDir = join(RULES_ROOT, entry);
    if (!statSync(ruleDir).isDirectory()) continue;
    const hasRules = readdirSync(ruleDir).some((file) => file.endsWith('.yaml'));
    if (!hasRules) continue;

    const fixtureDir = join(FIXTURES_ROOT, entry.toLowerCase());
    assert.ok(existsSync(fixtureDir), `missing golden fixtures for ${entry}`);
    const files = readdirSync(fixtureDir);
    assert.ok(files.some((file) => file.includes('.vulnerable.')), `${entry} missing vulnerable fixture`);
    assert.ok(files.some((file) => file.includes('.hardened.')), `${entry} missing hardened fixture`);
  }
});
