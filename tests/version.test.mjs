// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for engine version range checks.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { satisfiesEngineRange } from '../src/version.mjs';

test('satisfiesEngineRange accepts >= minimum', () => {
  assert.equal(satisfiesEngineRange('>=0.1.0', '0.1.0'), true);
  assert.equal(satisfiesEngineRange('>=0.1.0', '0.2.0'), true);
  assert.equal(satisfiesEngineRange('>=0.2.0', '0.1.0'), false);
});

test('satisfiesEngineRange treats a bare version as a minimum', () => {
  assert.equal(satisfiesEngineRange('0.1.0', '0.1.0'), true);
  assert.equal(satisfiesEngineRange('0.1.0', '0.2.0'), true);
  assert.equal(satisfiesEngineRange('0.2.0', '0.1.0'), false);
});
