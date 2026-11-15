// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview CI provider — LastMile "Hardener" framework.
 *
 * Three deterministic, offline facts about the repo's CI pipeline (read from
 * the CI config files themselves, never executing anything):
 *
 *   1. **No CI pipeline** — no CI config file is committed.
 *   2. **CI runs no tests** — a pipeline exists but no test command appears.
 *   3. **No coverage gate** — tests run, but no coverage tool is referenced.
 *
 * These are process signals (not code defects), so they are **advisories**
 * (reported, not scored) — same rationale as committed config secrets.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { isIgnoredDir } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */

/** CI config paths relative to the repo root (files or dirs to glob). */
const CI_LOCATIONS = [
  '.github/workflows', // dir — glob *.yml / *.yaml
  '.gitlab-ci.yml',
  '.circleci/config.yml',
  '.buildkite/pipeline.yml',
  'Jenkinsfile',
  'bitbucket-pipelines.yml',
  'azure-pipelines.yml',
  '.travis.yml',
];

/** A test-runner invocation anywhere in a CI config. */
const TEST_CMD_RE =
  /\b(npm (test|run test|run ci:test)|yarn test|pnpm test|bun test|pytest|python -m pytest|go test|cargo test|phpunit|composer test|composer run test|jest|vitest|mvn (test|verify)|gradle test|rspec|bundle exec rspec|make test|dotnet test)\b/i;

/** A coverage tool / flag reference in a CI config. */
const COVERAGE_RE = /codecov|coveralls|--cov\b|--coverage\b|coverage\.run|pytest-cov|nyc\b|\bc8\b|lcov|gcov|jest --coverage|\bcargo tarpaulin\b/i;

/** @type {Provider} */
export const ciProvider = {
  id: 'ci',
  name: 'CI pipeline',
  available: () => Promise.resolve(true),
  applicable: () => true,
  async run(_config, ctx) {
    const ciFiles = findCiFiles(ctx.repoRoot);
    if (ciFiles.length === 0) {
      ctx.log('  no CI pipeline detected');
      return [noCiFinding(ctx)];
    }

    ctx.log(`  ${ciFiles.length} CI file(s)`);
    /** @type {string[]} */
    const contents = [];
    for (const file of ciFiles) {
      try {
        contents.push(readFileSync(join(ctx.repoRoot, file), 'utf8'));
      } catch {
        // unreadable config — skip
      }
    }
    const all = contents.join('\n');

    if (!TEST_CMD_RE.test(all)) {
      ctx.log('  pipeline runs no test command');
      return [noTestsFinding(ciFiles[0])];
    }
    if (!COVERAGE_RE.test(all)) {
      ctx.log('  tests run without a coverage reference');
      return [noCoverageFinding(ciFiles[0])];
    }
    ctx.log('  tests + coverage detected — nothing to flag');
    return [];
  },
};

/**
 * Locate committed CI config files (repo-root convention), repo-relative.
 * @param {string} repoRoot
 * @returns {string[]} sorted, deduplicated repo-relative paths.
 */
export function findCiFiles(repoRoot) {
  /** @type {string[]} */
  const found = [];
  for (const location of CI_LOCATIONS) {
    const abs = join(repoRoot, location);
    if (!existsSync(abs)) continue;
    let stat;
    try {
      stat = statSync(abs);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      // Glob .yml / .yaml (and .json for Azure) one level deep.
      let entries;
      try {
        entries = readdirSync(abs);
      } catch {
        continue;
      }
      for (const name of entries.sort()) {
        if (/\.(ya?ml|json)$/i.test(name)) found.push(`${location}/${name}`);
      }
    } else {
      found.push(location);
    }
  }
  return [...new Set(found)].sort();
}

/**
 * The "no CI pipeline" advisory.
 * @param {RunContext} ctx
 * @returns {Finding}
 */
function noCiFinding(ctx) {
  return {
    id: 'ci:no-pipeline',
    kind: 'hygiene',
    file: ctx.targets[0] ? ctx.targets[0].replace(/^[/\\]+/, '') : '.',
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'qa',
    teardownId: null,
    title: 'No CI pipeline detected',
    message: 'No CI config file (.github/workflows, .gitlab-ci.yml, Jenkinsfile, …) was found — tests and checks are not enforced on every change.',
    fixSummary: 'Add a CI pipeline that installs dependencies and runs the test suite on every push.',
    source: { provider: 'ci', ruleId: 'no-pipeline' },
    dependency: null,
    advisory: true,
  };
}

/**
 * The "CI runs no tests" advisory.
 * @param {string} ciFile — repo-relative path of the first CI config.
 * @returns {Finding}
 */
function noTestsFinding(ciFile) {
  return {
    id: `ci:${ciFile}:no-tests`,
    kind: 'hygiene',
    file: ciFile,
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'qa',
    teardownId: null,
    title: 'CI pipeline runs no tests',
    message: 'A CI pipeline exists, but no test command (npm test, pytest, go test, …) was found in its config.',
    fixSummary: 'Add a test step to the pipeline so regressions are caught on every change.',
    source: { provider: 'ci', ruleId: 'no-tests' },
    dependency: null,
    advisory: true,
  };
}

/**
 * The "no coverage gate" advisory.
 * @param {string} ciFile
 * @returns {Finding}
 */
function noCoverageFinding(ciFile) {
  return {
    id: `ci:${ciFile}:no-coverage`,
    kind: 'hygiene',
    file: ciFile,
    line: null,
    column: null,
    severity: 'low',
    pillar: 'qa',
    teardownId: null,
    title: 'CI runs tests without a coverage gate',
    message: 'Tests run in CI, but no coverage tool (jest --coverage, pytest-cov, codecov, …) is referenced — coverage is not tracked or enforced.',
    fixSummary: 'Add coverage instrumentation and fail the pipeline when coverage drops below a threshold.',
    source: { provider: 'ci', ruleId: 'no-coverage' },
    dependency: null,
    advisory: true,
  };
}
