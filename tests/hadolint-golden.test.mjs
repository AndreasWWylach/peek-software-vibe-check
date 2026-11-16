// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Hadolint golden test — runs the real `hadolint` binary over a
 * deliberately-bad Dockerfile fixture and asserts the provider maps it. Mirrors
 * the checkov + Semgrep golden harnesses (§7.3). Skipped when `hadolint` is not
 * on PATH.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommandCapture } from '../src/proc.mjs';
import { parseHadolintJson } from '../src/providers/hadolint.mjs';

const FIXTURE = fileURLToPath(new URL('./fixtures/hadolint/Dockerfile', import.meta.url));
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url)); // tests/ → repo root

const hadolintAvailable = commandAvailable('hadolint');
const skipReason = hadolintAvailable ? false : 'hadolint is not installed — e2e skipped';

test('hadolint golden: bad Dockerfile fires DL rules as advisory runtime findings', { skip: skipReason }, () => {
  const { stdout } = runCommandCapture('hadolint', ['--format', 'json', FIXTURE]);
  const findings = parseHadolintJson(stdout, REPO_ROOT);
  const codes = findings.map((f) => f.source.ruleId);
  assert.ok(codes.includes('DL3006'), `expected DL3006, got ${codes.join(', ')}`);
  assert.ok(codes.includes('DL3008'), `expected DL3008, got ${codes.join(', ')}`);
  for (const f of findings) {
    assert.equal(f.kind, 'hygiene');
    assert.equal(f.pillar, 'runtime');
    assert.equal(f.advisory, true);
  }
});
