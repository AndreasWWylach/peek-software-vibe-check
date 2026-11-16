// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Bandit golden test — runs the real `bandit` binary over a
 * fixture and asserts the provider maps shell/SQL findings to teardowns.
 * Skipped when `bandit` is missing.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommandCapture } from '../src/proc.mjs';
import { parseBanditJson } from '../src/providers/bandit.mjs';

const FIXTURE = fileURLToPath(new URL('./fixtures/bandit/vuln.py', import.meta.url));

const banditAvailable = commandAvailable('bandit');
const skipReason = banditAvailable ? false : 'bandit is not installed — e2e skipped';

test('bandit golden: shell=True + SQL concat fire TD-042/TD-033 as scored findings', { skip: skipReason }, () => {
  const { stdout } = runCommandCapture('bandit', ['-r', FIXTURE, '-f', 'json', '-q']);
  const findings = parseBanditJson(stdout, FIXTURE);

  const shell = findings.find((f) => f.teardownId === 'TD-042');
  assert.ok(shell, `expected a TD-042 shell finding, got ${findings.map((f) => f.source.ruleId).join(', ')}`);
  assert.equal(shell.kind, 'teardown');
  assert.equal(shell.advisory, false);
  assert.equal(shell.pillar, 'security');

  const sql = findings.find((f) => f.teardownId === 'TD-033');
  assert.ok(sql, `expected a TD-033 SQL finding, got ${findings.map((f) => f.source.ruleId).join(', ')}`);
  assert.equal(sql.kind, 'teardown');
  assert.equal(sql.advisory, false);
});
