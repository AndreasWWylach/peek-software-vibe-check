// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the Firebase/Firestore security-rules provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { firebaseProvider, isOpenRules, requiresAuth } from '../src/providers/firebase.mjs';

/** Run the provider against a temp repo whose content is built by `setup`.
 * @param {(root: string) => void} setup
 * @returns {Promise<import('../src/types.mjs').Finding[]>}
 */
async function runFixture(setup) {
  const root = mkdtempSync(join(tmpdir(), 'vibe-check-firebase-'));
  try {
    await setup(root);
    return await firebaseProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [root], log: () => {} }),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

/** A package.json that marks Firestore (via firebase-admin). */
const FIREBASE_ADMIN_PKG = JSON.stringify({ dependencies: { 'firebase-admin': '^12' } });

test('isOpenRules + requiresAuth classify rules content', () => {
  assert.equal(isOpenRules('match /{d=**} { allow read, write: if true; }'), true);
  assert.equal(isOpenRules('allow read, write;'), true);
  assert.equal(isOpenRules('allow read, write: if request.auth != null;'), false);
  assert.equal(requiresAuth('allow read: if request.auth != null;'), true);
  assert.equal(requiresAuth('allow read: if true;'), false);
});

test('firebase provider flags Firestore with no rules file', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(join(root, 'package.json'), FIREBASE_ADMIN_PKG);
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'missing-rules');
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].teardownId, 'TD-008');
});

test('firebase provider flags open (if true) rules as critical', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(join(root, 'firestore.rules'), 'match /{d=**} { allow read, write: if true; }');
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'open-rules');
  assert.equal(findings[0].severity, 'critical');
});

test('firebase provider flags rules that do not require auth', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(
      join(root, 'firestore.rules'),
      'match /{d=**} { allow read: if request.time < timestamp.date(2030, 1, 1); }',
    );
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'no-auth');
  assert.equal(findings[0].severity, 'high');
});

test('firebase provider stays silent on auth-required rules', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(
      join(root, 'firestore.rules'),
      'match /tenants/{tenantId}/{d=**} { allow read, write: if request.auth != null && request.auth.uid == tenantId; }',
    );
  });
  assert.equal(findings.length, 0);
});

test('firebase provider is silent for non-Firebase apps', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { express: '^5' } }));
  });
  assert.equal(findings.length, 0);
});
