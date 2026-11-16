// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview gosec golden test — runs the real `gosec` binary over a Go
 * fixture module and asserts the provider maps command/SQL findings to
 * teardowns. Skipped when `gosec` is missing.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { commandAvailable, runCommandCapture } from '../src/proc.mjs';
import { parseGosecJson } from '../src/providers/gosec.mjs';

const FIXTURES_ROOT = fileURLToPath(new URL('./fixtures/gosec', import.meta.url));

const gosecAvailable = commandAvailable('gosec');
const skipReason = gosecAvailable ? false : 'gosec is not installed — e2e skipped';

test('gosec golden: command + SQL concat fire TD-042/TD-033 as scored findings', { skip: skipReason }, () => {
  const { stdout } = runCommandCapture('gosec', ['-fmt', 'json', '-quiet', './...'], { cwd: FIXTURES_ROOT });
  const findings = parseGosecJson(stdout, FIXTURES_ROOT);

  const shell = findings.find((f) => f.teardownId === 'TD-042');
  assert.ok(shell, `expected a TD-042 command finding, got ${findings.map((f) => f.source.ruleId).join(', ')}`);
  assert.equal(shell.kind, 'teardown');
  assert.equal(shell.advisory, false);
  assert.equal(shell.pillar, 'security');

  const sql = findings.find((f) => f.teardownId === 'TD-033');
  assert.ok(sql, `expected a TD-033 SQL finding, got ${findings.map((f) => f.source.ruleId).join(', ')}`);
  assert.equal(sql.kind, 'teardown');
  assert.equal(sql.advisory, false);
});
