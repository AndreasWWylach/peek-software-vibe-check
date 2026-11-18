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
import { parseRulesScope, scanFirestoreQueries, matchScopeRule } from '../src/firestore/scope.mjs';

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
  assert.equal(isOpenRules('match /{d=**} { allow write: if true; }'), true);
  assert.equal(isOpenRules('allow read, write: if request.auth != null;'), false);
  // Scoped public read (write denied) is a deliberate pattern — not "open".
  assert.equal(isOpenRules('match /rvSlugs/{slug} { allow read: if true; allow write: if false; }'), false);
  assert.equal(requiresAuth('allow read: if request.auth != null;'), true);
  assert.equal(requiresAuth('allow read: if true;'), false);
});

test('firebase provider flags Firestore with no rules file', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(join(root, 'package.json'), FIREBASE_ADMIN_PKG);
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'missing-rules');
  assert.equal(findings[0].severity, 'medium'); // server-only (Admin SDK) access
  assert.equal(findings[0].teardownId, 'TD-008');
});

test('firebase provider escalates client-direct Firestore with no rules to critical', async () => {
  const findings = await runFixture((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { firebase: '^12' } }));
    writeFileSync(
      join(root, 'src', 'db.ts'),
      "import { getFirestore } from 'firebase/firestore';\nexport const db = getFirestore();\n",
    );
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'missing-rules');
  assert.equal(findings[0].severity, 'critical');
});

test('firebase provider flags Cloud Functions with no visible auth check', async () => {
  const findings = await runFixture((root) => {
    mkdirSync(join(root, 'functions'), { recursive: true });
    writeFileSync(
      join(root, 'functions', 'package.json'),
      JSON.stringify({ dependencies: { 'firebase-functions': '^5', 'firebase-admin': '^12' } }),
    );
    writeFileSync(
      join(root, 'functions', 'publicFn.ts'),
      "import * as functions from 'firebase-functions';\nexport const hello = functions.https.onCall(() => 'hi');\n",
    );
  });
  const auth = findings.filter((finding) => finding.source.ruleId === 'handler-no-auth');
  assert.equal(auth.length, 1);
  assert.equal(auth[0].teardownId, 'TD-032');
  assert.equal(auth[0].severity, 'low');
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

test('firebase provider stays silent on scoped public reads (write denied)', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(
      join(root, 'firestore.rules'),
      'match /rvSlugs/{slug} { allow read: if true; allow write: if false; }\nmatch /{d=**} { allow read, write: if request.auth != null; }',
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

test('parseRulesScope extracts per-path required fields and skips public reads', () => {
  const scope = parseRulesScope(`
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function uid() { return request.auth.uid; }
    function signedIn() { return request.auth != null; }
    match /rvFilms/{filmId}/assets/{assetId} {
      allow read: if signedIn() && resource.data.get('ownerUid', '') == uid();
      allow write: if false;
    }
    match /rvScreenings/{screeningId} {
      allow read: if resource.data.status == 'onSale';
      allow write: if false;
    }
  }
}
`);
  const assets = scope.get('rvFilms/assets');
  assert.ok(assets, 'expected rvFilms/assets scope rule');
  assert.equal(assets?.requiresAuth, true);
  assert.ok(assets?.required.has('ownerUid'));
  // rvScreenings has a public (no-auth) read → no blanket scope rule.
  assert.equal(scope.has('rvScreenings'), false);
});

test('scanFirestoreQueries extracts path key, where fields, and read-ness', () => {
  const queries = scanFirestoreQueries(
    "onSnapshot(query(collection(getDb(), 'rvFilms', filmId, 'assets'), where('ownerUid', '==', uid)), cb);\n" +
      "setDoc(doc(getDb(), 'rvFilms', filmId), data);",
  );
  assert.equal(queries.length, 1, 'writes are not read queries');
  assert.equal(queries[0]?.pathKey, 'rvFilms/assets');
  assert.equal(queries[0]?.whereFields.has('ownerUid'), true);
  assert.equal(queries[0]?.read, true);
});

test('firebase provider flags a client query missing the rule-required scope', async () => {
  const findings = await runFixture((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(
      join(root, 'firestore.rules'),
      "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    function uid() { return request.auth.uid; }\n    match /rvFilms/{filmId}/assets/{assetId} {\n      allow read: if resource.data.get('ownerUid', '') == uid();\n      allow write: if false;\n    }\n    match /rvScreenings/{screeningId} {\n      allow read: if resource.data.status == 'onSale';\n      allow write: if false;\n    }\n  }\n}\n",
    );
    writeFileSync(
      join(root, 'src', 'queries.ts'),
      "import { collection, getFirestore, onSnapshot, query, where } from 'firebase/firestore';\n" +
        "const db = getFirestore();\n" +
        "const filmId = 'x';\n" +
        "// vulnerable: no ownerUid constraint (filmId is a dynamic arg, like real code)\n" +
        "onSnapshot(query(collection(db, 'rvFilms', filmId, 'assets')), () => {});\n" +
        "// hardened: constrained\n" +
        "onSnapshot(query(collection(db, 'rvFilms', filmId, 'assets'), where('ownerUid', '==', 'u')), () => {});\n" +
        "// public collection: no auth scope required\n" +
        "onSnapshot(query(collection(db, 'rvScreenings')), () => {});\n",
    );
  });
  const mismatches = findings.filter((finding) => finding.source.ruleId === 'rule-query-mismatch');
  assert.equal(mismatches.length, 1, 'expected exactly one rule/query mismatch');
  assert.equal(mismatches[0]?.teardownId, 'TD-008');
  assert.equal(mismatches[0]?.severity, 'high');
  assert.ok(String(mismatches[0]?.message).includes('ownerUid'));
});
