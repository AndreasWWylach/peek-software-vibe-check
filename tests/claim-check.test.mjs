// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for the agent-log claim cross-check.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseFixClaims, verifyFixClaims } from '../src/claim-check.mjs';

/** @param {Partial<import('../src/types.mjs').Finding> & Pick<import('../src/types.mjs').Finding, 'kind' | 'title'>} input
 * @returns {import('../src/types.mjs').Finding} */
function finding(input) {
  return {
    id: input.id ?? `id-${Math.random()}`,
    file: input.file ?? 'src/x.ts',
    line: input.line ?? 3,
    column: null,
    severity: input.severity ?? 'high',
    pillar: input.pillar ?? 'security',
    teardownId: input.teardownId ?? null,
    message: null,
    fixSummary: null,
    source: input.source ?? { provider: 'semgrep', ruleId: 'rule-x' },
    dependency: null,
    ...input,
  };
}

test('parseFixClaims recognizes only the exact checklist shape', () => {
  const claims = parseFixClaims(`
## vibe-check remediation — 2026-11-22

- [x] TD-033 — fixed in src/db/users.ts
- [ ] TD-019 — false positive, bundled third-party script
- [x] TD-057 - fixed in backend/proxy.js
- not a claim line
- [x] TD-999 — fixed in somewhere (parses; verification marks it not-checkable)
`);
  assert.equal(claims.length, 4);
  assert.deepEqual(claims[0], { teardownId: 'TD-033', file: 'src/db/users.ts', intent: 'fixed', detail: 'fixed in src/db/users.ts' });
  assert.deepEqual(claims[1], { teardownId: 'TD-019', file: null, intent: 'left', detail: 'false positive, bundled third-party script' });
  assert.deepEqual(claims[2], { teardownId: 'TD-057', file: 'backend/proxy.js', intent: 'fixed', detail: 'fixed in backend/proxy.js' });
  assert.equal(claims[3].teardownId, 'TD-999');
});

test('verifyFixClaims contradicts a claim the scan disproves', () => {
  const findings = [
    finding({ kind: 'teardown', teardownId: 'TD-033', file: 'src/db/users.ts', title: 'SQL concat' }),
  ];
  const verified = verifyFixClaims(findings, ['TD-033'], [
    { teardownId: 'TD-033', file: 'src/db/users.ts', intent: 'fixed', detail: 'fixed in src/db/users.ts' },
  ]);
  assert.equal(verified[0].status, 'contradicted');
});

test('verifyFixClaims holds a claim the scan no longer reports', () => {
  const verified = verifyFixClaims([], ['TD-033'], [
    { teardownId: 'TD-033', file: 'src/db/users.ts', intent: 'fixed', detail: 'fixed in src/db/users.ts' },
  ]);
  assert.equal(verified[0].status, 'holds');
});

test('verifyFixClaims: same TD in a DIFFERENT file still holds for the claimed file', () => {
  const verified = verifyFixClaims(
    [finding({ kind: 'teardown', teardownId: 'TD-054', file: 'src/other.ts', title: 'Silent failure' })],
    ['TD-054'],
    [{ teardownId: 'TD-054', file: 'src/chat-view.js', intent: 'fixed', detail: 'fixed in src/chat-view.js' }],
  );
  assert.equal(verified[0].status, 'holds');
});

test('verifyFixClaims marks unscanned TDs as not-checkable, never holds', () => {
  const verified = verifyFixClaims([], ['TD-016'], [
    { teardownId: 'TD-002', file: 'src/ai.ts', intent: 'fixed', detail: 'fixed in src/ai.ts' },
  ]);
  assert.equal(verified[0].status, 'not-checkable');
});

test('verifyFixClaims acknowledges declared-unfixed claims without contradiction', () => {
  const verified = verifyFixClaims(
    [finding({ kind: 'teardown', teardownId: 'TD-019', file: 'src/big.ts', title: 'Monolithic file' })],
    ['TD-019'],
    [{ teardownId: 'TD-019', file: 'src/big.ts', intent: 'left', detail: 'false positive, bundled script' }],
  );
  assert.equal(verified[0].status, 'acknowledged');
});
