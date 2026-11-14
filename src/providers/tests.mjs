// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests provider — the QA-pillar test signal (docs §8.1).
 *
 * Two cheap, deterministic, offline facts a scanner can honestly state about a
 * codebase's tests, without ever running them:
 *
 *   1. **Presence** — does the repo have any test files at all? No tests is a
 *      QA finding on its own ("no test signal to score").
 *   2. **Assertions** — does each test file actually assert anything? A test
 *      file with no assertion call is the "hallucinated test" smell (TD-017):
 *      it ran, it did not throw, and it verified nothing.
 *
 * Both are heuristics (path conventions + a small assertion-call whitelist),
 * so they are scored low/medium, never critical, and are worded as signals.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { hasNonCodeExt, isIgnoredDir, isTestFile } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */

/** The teardown for "hallucinated tests" (tests that verify nothing). */
const TEARDOWN_ID = 'TD-017';

/** Fallbacks when the vendored catalog does not yet carry TD-017. */
const DEFAULTS = {
  pillar: /** @type {Pillar} */ ('qa'),
  severity: /** @type {Severity} */ ('low'),
  fixSummary:
    'Assert real outcomes — expected vs actual, thrown errors, or return values — not just "the call did not throw".',
};

/**
 * Common assertion call shapes across Jest/Vitest/Mocha/Chai/Node/Python/PHP. A
 * test file containing none of these almost certainly verifies nothing.
 */
const ASSERTION_RE =
  /(expect\s*\(|\.should\s*\(|\.should\b|assert[A-Z_]|\bassert\b|assert\s*\(|fail\s*\()/i;

/**
 * Test *declaration* shapes — a file that defines test cases. Fakes, mocks and
 * helpers that merely live under a `test/` dir are not test cases and are not
 * judged for assertions.
 */
const TEST_DECL_RE =
  /(\b(test|it|describe|spec|suite)\s*\(|def\s+test_|function\s+test|@Test|@pytest\.mark)/i;

/** @type {Provider} */
export const testsProvider = {
  id: 'tests',
  name: 'Tests (QA signal)',
  // Pure file reading — no binary to install, always available.
  available: () => Promise.resolve(true),
  applicable: () => true,
  async run(_config, ctx) {
    const targets = ctx.targets.filter((target) => existsSync(target));
    if (targets.length === 0) {
      ctx.log('  no existing targets — nothing to scan');
      return [];
    }

    /** @type {string[]} */
    const seen = [];
    for (const target of targets) {
      collectFiles(target, ctx.repoRoot, seen);
    }
    const testFiles = [...new Set(seen)].filter(isTestFile);

    if (testFiles.length === 0) {
      ctx.log('  no test files found');
      return [noTestsFinding(ctx)];
    }

    /** @type {Finding[]} */
    const findings = [];
    let withoutAssertions = 0;
    for (const repoFile of testFiles) {
      let content = '';
      try {
        content = readFileSync(join(ctx.repoRoot, repoFile), 'utf8');
      } catch {
        continue;
      }
      // Only judge files that actually declare tests — helpers/fakes/mocks
      // under a test/ dir are fixtures, not test cases.
      if (!TEST_DECL_RE.test(content)) continue;
      if (!hasAssertions(content)) {
        withoutAssertions += 1;
        findings.push(noAssertionFinding(repoFile));
      }
    }
    ctx.log(`  ${testFiles.length} test file(s), ${withoutAssertions} without assertions`);
    return findings;
  },
};

/**
 * Does a test file's content contain any recognizable assertion call?
 * @param {string} content — full file text.
 * @returns {boolean}
 */
export function hasAssertions(content) {
  return ASSERTION_RE.test(content);
}

/**
 * Recursively collect repo-relative file paths under `dir`, skipping junk dirs
 * (node_modules, dist, …) and data/docs files.
 * @param {string} dir — absolute directory.
 * @param {string} repoRoot
 * @param {string[]} out — accumulates repo-relative paths.
 */
function collectFiles(dir, repoRoot, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (isIgnoredDir(entry.name)) continue;
      collectFiles(abs, repoRoot, out);
    } else if (entry.isFile()) {
      const repoFile = toRepoFile(abs, repoRoot);
      if (isIgnoredDir(repoFile) || hasNonCodeExt(repoFile)) continue;
      out.push(repoFile);
    }
  }
}

/**
 * The "no tests at all" QA finding, anchored to the first scanned target.
 * @param {RunContext} ctx
 * @returns {Finding}
 */
function noTestsFinding(ctx) {
  const first = ctx.targets[0];
  return {
    id: 'tests:no-tests',
    kind: 'hygiene',
    file: first ? toRepoFile(first, ctx.repoRoot) : '.',
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'qa',
    teardownId: null,
    title: 'No unit tests detected',
    message: 'No test files found under the scanned targets — the QA pillar has no test signal to score.',
    fixSummary: 'Add unit tests for the core business logic, the edge cases, and the paths the app monetizes.',
    source: { provider: 'tests', ruleId: 'no-tests' },
    dependency: null,
  };
}

/**
 * The TD-017 "hallucinated test" heuristic finding.
 * @param {string} repoFile
 * @returns {Finding}
 */
function noAssertionFinding(repoFile) {
  return {
    id: `tests:${repoFile}:no-assertions`,
    kind: 'teardown',
    file: repoFile,
    line: null,
    column: null,
    severity: DEFAULTS.severity,
    pillar: DEFAULTS.pillar,
    teardownId: TEARDOWN_ID,
    title: 'Test file with no assertions',
    message: 'No assertion calls (expect/assert/should…) detected in this test file — it may not actually verify anything.',
    fixSummary: DEFAULTS.fixSummary,
    source: { provider: 'tests', ruleId: 'no-assertions' },
    dependency: null,
  };
}

/**
 * Normalize an absolute path to a repo-relative one.
 * @param {string} location
 * @param {string} repoRoot
 * @returns {string}
 */
function toRepoFile(location, repoRoot) {
  if (isAbsolute(location)) {
    return relative(repoRoot, location).replace(/^[/\\]+/, '');
  }
  return location.replace(/^[/\\]+/, '');
}
