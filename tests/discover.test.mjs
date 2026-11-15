// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for source-directory discovery.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverSourceDirs } from '../src/discover.mjs';

test('discoverSourceDirs finds code dirs and skips docs/data/ignored', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-check-discover-'));
  try {
    mkdirSync(join(root, 'src'), { recursive: true });
    mkdirSync(join(root, 'scripts'), { recursive: true });
    mkdirSync(join(root, 'docs'), { recursive: true });
    mkdirSync(join(root, 'data'), { recursive: true });
    mkdirSync(join(root, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(join(root, 'src', 'app.ts'), 'export const x = 1;\n');
    writeFileSync(join(root, 'scripts', 'deploy.mjs'), 'console.log("deploy");\n');
    writeFileSync(join(root, 'docs', 'readme.md'), '# docs\n');
    writeFileSync(join(root, 'data', 'config.json'), '{}\n');
    writeFileSync(join(root, 'node_modules', 'pkg', 'index.js'), 'module.exports = 1;\n');

    assert.deepEqual(discoverSourceDirs(root, ['typescript', 'javascript']), ['scripts/', 'src/']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('discoverSourceDirs returns [] for languages with no matching code', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-check-discover-'));
  try {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src', 'app.py'), 'print(1)\n');
    assert.deepEqual(discoverSourceDirs(root, ['php']), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
