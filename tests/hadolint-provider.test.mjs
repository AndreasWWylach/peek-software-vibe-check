// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the Hadolint (Dockerfile) provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hadolintProvider, findDockerfiles, parseHadolintJson } from '../src/providers/hadolint.mjs';

test('parseHadolintJson maps levels to severity + advisory runtime findings', () => {
  const stdout = JSON.stringify([
    { code: 'DL3006', level: 'warning', file: '/repo/Dockerfile', line: 1, column: 1, message: 'Always tag the version of an image explicitly' },
    { code: 'DL3015', level: 'info', file: '/repo/Dockerfile', line: 2, column: 1, message: 'Avoid additional packages by specifying --no-install-recommends' },
    { code: 'DL3002', level: 'error', file: '/repo/docker/Dockerfile.prod', line: 10, column: 1, message: 'Last USER should not be root' },
  ]);

  const findings = parseHadolintJson(stdout, '/repo');
  assert.equal(findings.length, 3);

  const warning = findings.find((f) => f.source.ruleId === 'DL3006');
  assert.ok(warning);
  assert.equal(warning.severity, 'medium');
  assert.equal(warning.file, 'Dockerfile');
  assert.equal(warning.line, 1);
  assert.equal(warning.pillar, 'runtime');
  assert.equal(warning.advisory, true);
  assert.equal(warning.kind, 'hygiene');
  assert.equal(warning.teardownId, null);

  const info = findings.find((f) => f.source.ruleId === 'DL3015');
  assert.equal(info?.severity, 'low');

  const error = findings.find((f) => f.source.ruleId === 'DL3002');
  assert.equal(error?.severity, 'high');
  assert.equal(error?.file, 'docker/Dockerfile.prod');
});

test('findDockerfiles collects Dockerfile* under targets + root', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-hadolint-'));
  try {
    mkdirSync(join(root, 'docker'), { recursive: true });
    writeFileSync(join(root, 'Dockerfile'), 'FROM node:22\n');
    writeFileSync(join(root, 'docker', 'Dockerfile.prod'), 'FROM node:22\n');
    writeFileSync(join(root, 'docker', 'README.md'), 'not a dockerfile\n');
    writeFileSync(join(root, 'app.js'), 'export const x = 1;\n');

    const found = findDockerfiles(root, [join(root, 'docker')]).sort();
    assert.deepEqual(found, ['Dockerfile', 'docker/Dockerfile.prod']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('hadolint provider skips gracefully when the repo has no Dockerfiles', async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-hadolint-'));
  try {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src', 'app.js'), 'export const x = 1;\n');
    const findings = await hadolintProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'src')], log: () => {} }),
    );
    assert.deepEqual(findings, []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
