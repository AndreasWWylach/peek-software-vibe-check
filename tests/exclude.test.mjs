// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the config `exclude` path matching.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isExcludedPath } from '../src/run.mjs';

test('isExcludedPath matches exact dir and subtree prefixes', () => {
  const excludes = ['examples/', 'docs/legacy'];
  assert.equal(isExcludedPath(excludes, 'examples'), true);
  assert.equal(isExcludedPath(excludes, 'examples/'), true);
  assert.equal(isExcludedPath(excludes, 'examples/sample-app'), true);
  assert.equal(isExcludedPath(excludes, 'examples/sample-app/src/index.ts'), true);
  assert.equal(isExcludedPath(excludes, 'docs/legacy'), true);
  assert.equal(isExcludedPath(excludes, 'docs/legacy/old.md'), true);
  assert.equal(isExcludedPath(excludes, 'docs'), false);
  assert.equal(isExcludedPath(excludes, 'src/index.ts'), false);
});

test('isExcludedPath does not over-match by shared prefix', () => {
  // "examples/" must not exclude "examples-extra/".
  const excludes = ['examples/'];
  assert.equal(isExcludedPath(excludes, 'examples-extra'), false);
  assert.equal(isExcludedPath(excludes, 'examples-extra/app.ts'), false);
});
