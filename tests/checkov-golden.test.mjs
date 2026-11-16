// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Checkov golden test — runs the real `checkov` binary over small
 * IaC fixtures and asserts the provider maps them correctly. Mirrors the
 * Semgrep golden harness (§7.3): the fixture that *is* vulnerable fires, and
 * the classification (pillar/severity/advisory) is as designed.
 *
 * Skipped when `checkov` is not on PATH — the provider itself degrades
 * gracefully, and these tests are the credibility gate only when installed.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommandCapture } from '../src/proc.mjs';
import { parseCheckovJson } from '../src/providers/checkov.mjs';

/** Absolute path to the checkov fixtures. */
const FIXTURES_ROOT = fileURLToPath(new URL('./fixtures/checkov', import.meta.url));

const checkovAvailable = commandAvailable('checkov');
const skipReason = checkovAvailable ? false : 'checkov is not installed — e2e skipped';

/**
 * Run checkov over one fixture file (as the provider would) and parse it.
 * @param {string} name — fixture basename.
 * @returns {import('../src/types.mjs').Finding[]}
 */
function scanFixture(name) {
  const { stdout } = runCommandCapture('checkov', [
    '--output', 'json',
    '--quiet',
    '--skip-framework', 'secrets',
    '--file', join(FIXTURES_ROOT, name),
  ]);
  return parseCheckovJson(stdout, FIXTURES_ROOT);
}

test('checkov golden: Dockerfile fires CKV_DOCKER_2/3 as advisory runtime findings', { skip: skipReason }, () => {
  const findings = scanFixture('Dockerfile');
  const ids = findings.map((f) => f.source.ruleId);
  assert.ok(ids.includes('CKV_DOCKER_2'), `expected CKV_DOCKER_2, got ${ids.join(', ')}`);
  assert.ok(ids.includes('CKV_DOCKER_3'), `expected CKV_DOCKER_3, got ${ids.join(', ')}`);
  for (const f of findings) {
    assert.equal(f.kind, 'hygiene');
    assert.equal(f.pillar, 'runtime');
    assert.equal(f.advisory, true);
  }
});

test('checkov golden: IAM fixture fires wildcard checks as scored high security findings', { skip: skipReason }, () => {
  const findings = scanFixture('iam.tf');
  const ids = findings.map((f) => f.source.ruleId);
  assert.ok(ids.includes('CKV_AWS_63'), `expected CKV_AWS_63 (Action wildcard), got ${ids.join(', ')}`);
  const scored = findings.filter((f) => !f.advisory);
  assert.ok(scored.length > 0, 'expected at least one scored (high) IAM finding');
  for (const f of scored) {
    assert.equal(f.severity, 'high');
    assert.equal(f.pillar, 'security');
  }
});
