// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Trivy golden test — runs the real `trivy` binary over a
 * fixture containing a recognizable secret (secret scan is offline — no vuln
 * DB needed) and asserts the provider maps it. Skipped when `trivy` is missing.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommandCapture } from '../src/proc.mjs';
import { parseTrivyJson } from '../src/providers/trivy.mjs';

const FIXTURE = fileURLToPath(new URL('./fixtures/trivy/leak.txt', import.meta.url));
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url)); // tests/ → repo root

const trivyAvailable = commandAvailable('trivy');
const skipReason = trivyAvailable ? false : 'trivy is not installed — e2e skipped';

test('trivy golden: stripe fixture fires stripe-secret-token as advisory security finding', { skip: skipReason }, () => {
  const { stdout } = runCommandCapture('trivy', ['fs', '--scanners', 'secret', '--format', 'json', '--quiet', FIXTURE]);
  const findings = parseTrivyJson(stdout, REPO_ROOT);
  assert.ok(findings.length >= 1, 'expected at least one secret finding');
  const secret = findings.find((f) => f.source.ruleId === 'stripe-secret-token');
  assert.ok(secret, `expected stripe-secret-token, got ${findings.map((f) => f.source.ruleId).join(', ')}`);
  assert.equal(secret.severity, 'critical');
  assert.equal(secret.pillar, 'security');
  assert.equal(secret.advisory, true);
  assert.equal(secret.kind, 'hygiene');
  // The secret value must never leak into a finding.
  assert.ok(!JSON.stringify(secret).includes('sk_live_'), 'secret value must not leak');
});
