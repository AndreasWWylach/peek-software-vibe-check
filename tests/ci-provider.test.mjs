// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the CI-pipeline provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ciProvider, findCiFiles } from '../src/providers/ci.mjs';

/**
 * @param {Record<string, string>} files — repo-relative path → content.
 * @returns {Promise<import('../src/types.mjs').Finding[]>}
 */
async function scan(files) {
  const root = mkdtempSync(join(tmpdir(), 'vibe-ci-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(root, rel);
      mkdirSync(join(abs, '..'), { recursive: true });
      writeFileSync(abs, content);
    }
    return await ciProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'src')], log: () => {} }),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('no CI config → no-pipeline advisory', async () => {
  const findings = await scan({ 'src/app.js': 'export const x = 1;\n' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'no-pipeline');
  assert.equal(findings[0].advisory, true);
  assert.equal(findings[0].pillar, 'qa');
});

test('CI pipeline with no test command → no-tests advisory', async () => {
  const findings = await scan({
    '.github/workflows/ci.yml': 'name: ci\njobs:\n  build:\n    steps:\n      - run: echo hi\n',
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'no-tests');
});

test('CI pipeline with tests but no coverage → no-coverage advisory', async () => {
  const findings = await scan({
    '.gitlab-ci.yml': 'test:\n  script:\n    - npm test\n',
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'no-coverage');
});

test('CI pipeline with tests + coverage → silent', async () => {
  const findings = await scan({
    '.github/workflows/ci.yml': 'steps:\n  - run: npm test\n  - run: npx jest --coverage\n',
  });
  assert.equal(findings.length, 0);
});

test('findCiFiles discovers workflow files and root configs', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-ci-files-'));
  try {
    mkdirSync(join(root, '.github', 'workflows'), { recursive: true });
    writeFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'x');
    writeFileSync(join(root, '.github', 'workflows', 'deploy.yaml'), 'x');
    writeFileSync(join(root, '.github', 'workflows', 'README.md'), 'x'); // not yaml
    writeFileSync(join(root, '.gitlab-ci.yml'), 'x');
    const found = findCiFiles(root);
    assert.deepEqual(found, ['.github/workflows/ci.yml', '.github/workflows/deploy.yaml', '.gitlab-ci.yml']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
