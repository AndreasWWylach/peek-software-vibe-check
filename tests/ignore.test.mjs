// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the shared path filters (junk dirs, env files,
 * non-code extensions, and test/fixture files).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hasNonCodeExt, isEnvFile, isIgnoredDir, isTestFile } from '../src/ignore.mjs';

test('isIgnoredDir flags dependency/build/cache dirs anywhere in the path', () => {
  assert.equal(isIgnoredDir('node_modules/react/index.js'), true);
  assert.equal(isIgnoredDir('src/dist/bundle.js'), true);
  assert.equal(isIgnoredDir('src/app.ts'), false);
});

test('isEnvFile flags .env and .env.local but not source files', () => {
  assert.equal(isEnvFile('.env'), true);
  assert.equal(isEnvFile('server/.env.production'), true);
  assert.equal(isEnvFile('src/env.ts'), false);
});

test('hasNonCodeExt flags data/docs extensions', () => {
  assert.equal(hasNonCodeExt('data/sample.json'), true);
  assert.equal(hasNonCodeExt('README.md'), true);
  assert.equal(hasNonCodeExt('src/app.ts'), false);
});

test('isTestFile flags test/spec/fixture files and dirs', () => {
  assert.equal(isTestFile('src/test/inbound.test.js'), true);
  assert.equal(isTestFile('src/foo.spec.ts'), true);
  assert.equal(isTestFile('tests/test_helpers.py'), true);
  assert.equal(isTestFile('src/__tests__/utils.ts'), true);
  assert.equal(isTestFile('test/foo_test.py'), true);
  assert.equal(isTestFile('src/mocks/api.ts'), true);
});

test('isTestFile does not flag ordinary source files', () => {
  assert.equal(isTestFile('src/contest.js'), false);
  assert.equal(isTestFile('src/testimonials.ts'), false);
  assert.equal(isTestFile('src/specification.md'), false);
  assert.equal(isTestFile('src/app.ts'), false);
});
