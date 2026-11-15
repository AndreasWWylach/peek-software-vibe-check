// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Hygiene golden test harness — every `rules/hygiene/*.yaml` rule
 * must fire on its `.vulnerable.*` fixtures and stay silent on `.hardened.*`
 * fixtures. Same credibility gate as the teardown golden harness (docs §7.3),
 * applied to the always-on LastMile hardening rules.
 *
 * Skipped when `semgrep` is not on PATH.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommand } from '../src/proc.mjs';

/** Absolute path to the always-on hygiene rules root. */
const HYGIENE_ROOT = fileURLToPath(new URL('../rules/hygiene', import.meta.url));
/** Absolute path to the hygiene golden fixtures root. */
const FIXTURES_ROOT = fileURLToPath(new URL('./golden/fixtures/hygiene', import.meta.url));

const semgrepAvailable = commandAvailable('semgrep');
const skipReason = semgrepAvailable ? false : 'semgrep is not installed — hygiene golden tests skipped';

/**
 * Run semgrep once over a hygiene rule file and return a per-file finding count.
 * @param {string} ruleFile — `rules/hygiene/<name>.yaml`.
 * @param {string[]} fixturePaths — absolute paths to the fixture files.
 * @returns {Map<string, number>} fixture basename → finding count.
 */
function scanFixtures(ruleFile, fixturePaths) {
  const stdout = runCommand('semgrep', ['--config', ruleFile, '--json', '--no-git-ignore', ...fixturePaths]);
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

for (const entry of readdirSync(HYGIENE_ROOT)) {
  if (!entry.endsWith('.yaml')) continue;

  const name = entry.slice(0, -'.yaml'.length);
  const ruleFile = join(HYGIENE_ROOT, entry);
  const fixtureDir = join(FIXTURES_ROOT, name);
  const fixtures = existsSync(fixtureDir) ? readdirSync(fixtureDir) : [];
  const fixturePaths = fixtures.map((file) => join(fixtureDir, file));
  const counts = semgrepAvailable ? scanFixtures(ruleFile, fixturePaths) : new Map();

  for (const fixture of fixtures) {
    const mustFire = fixture.includes('.vulnerable.');
    const isHardened = fixture.includes('.hardened.');
    if (!mustFire && !isHardened) continue;

    const expectation = mustFire ? 'fires' : 'is silent';
    test(`hygiene golden: ${name} ${expectation} on ${fixture}`, { skip: skipReason }, () => {
      const count = counts.get(fixture) ?? 0;
      if (mustFire) {
        assert.ok(count > 0, `expected ${name} to fire on ${fixture}, got ${count} finding(s)`);
      } else {
        assert.equal(count, 0, `expected ${name} to be silent on ${fixture}, got ${count} finding(s)`);
      }
    });
  }
}

test('every hygiene rule has vulnerable + hardened golden fixtures', () => {
  for (const entry of readdirSync(HYGIENE_ROOT)) {
    if (!entry.endsWith('.yaml')) continue;
    const name = entry.slice(0, -'.yaml'.length);
    const fixtureDir = join(FIXTURES_ROOT, name);
    assert.ok(existsSync(fixtureDir), `missing hygiene golden fixtures for ${name}`);
    const files = readdirSync(fixtureDir);
    assert.ok(files.some((file) => file.includes('.vulnerable.')), `${name} missing vulnerable fixture`);
    assert.ok(files.some((file) => file.includes('.hardened.')), `${name} missing hardened fixture`);
  }
});
