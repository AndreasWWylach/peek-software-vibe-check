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
import { parseRulesScope, scanFirestoreQueries, scanFirestoreWrites, matchScopeRule } from '../src/firestore/scope.mjs';

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
  // rvScreenings has a public (no-auth) read → no blanket READ scope to enforce,
  // but the block still carries its write state (denied) for the write check.
  assert.equal(scope.get('rvScreenings')?.requiresAuth, false);
  assert.equal(scope.get('rvScreenings')?.writesDenied, true);
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

test('parseRulesScope resolves helper functions: auth and scope fields in bodies', () => {
  const scope = parseRulesScope(`
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() { return request.auth != null; }
    function uid() { return request.auth.uid; }
    function projectData(pid) { return get(/databases/$(database)/documents/projects/$(pid)).data; }
    function canManageProjectData(p) {
      return signedIn() && (p.get('ownerId', '') == uid() || uid() in p.get('admins', []));
    }
    match /projects/{projectId} {
      allow read: if canManageProjectData(projectData(projectId));
      allow write: if false;
    }
    // The same helper on another collection: auth yes, fields no (the fields
    // belong to the projects doc, not the personnel doc).
    match /projectPersonnel/{docId} {
      allow read: if canManageProjectData(projectData(projectId));
      allow write: if false;
    }
  }
}
`);
  const projects = scope.get('projects');
  assert.ok(projects, 'expected projects scope rule');
  assert.equal(projects?.requiresAuth, true);
  assert.equal(projects?.branches.length, 2, 'ownerId OR admins alternatives');
  assert.ok(projects?.branches.some((b) => b.length === 1 && b[0] === 'ownerId'));
  assert.ok(projects?.branches.some((b) => b.length === 1 && b[0] === 'admins'));
  const personnel = scope.get('projectPersonnel');
  assert.ok(personnel, 'expected projectPersonnel scope rule (auth-only)');
  assert.equal(personnel?.requiresAuth, true);
  assert.equal(personnel?.branches.every((b) => b.length === 0), true, 'no foreign-doc fields required');
});

test('parseRulesScope splits OR branches inside helper bodies (shoot-readable shape)', () => {
  const scope = parseRulesScope(`
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() { return request.auth != null; }
    function uid() { return request.auth.uid; }
    function shootData(sid) { return get(/databases/$(database)/documents/shoots/$(sid)).data; }
    function shootIsProjectLevel(s) {
      return signedIn() && (s.get('projectOwnerId', '') == uid() || uid() in s.get('projectAdmins', []));
    }
    function isNamedShootAdmin(s) { return signedIn() && uid() in s.get('adminPermissions', {}); }
    function isShootWriter(s) { return shootIsProjectLevel(s) || isNamedShootAdmin(s); }
    function shootReadable(sid) {
      let s = shootData(sid);
      return isShootWriter(s) || (signedIn() && s.get('archived', false) == false);
    }
    match /shoots/{shootId} {
      allow read: if shootReadable(shootId);
      allow write: if false;
    }
  }
}
`);
  const shoots = scope.get('shoots');
  assert.ok(shoots, 'expected shoots scope rule');
  assert.equal(shoots?.requiresAuth, true);
  // Four alternatives: projectOwnerId | projectAdmins | adminPermissions | archived.
  assert.equal(shoots?.branches.length, 4);
  const sets = shoots?.branches.map((b) => [...b].sort().join(','));
  assert.ok(sets?.includes('archived'), `expected an archived-only branch, got ${JSON.stringify(sets)}`);
  assert.ok(sets?.includes('projectOwnerId'), `expected a projectOwnerId branch, got ${JSON.stringify(sets)}`);
});

test('firebase provider accepts a query satisfying any rule branch (archived filter)', async () => {
  const findings = await runFixture((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(
      join(root, 'firestore.rules'),
      "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    function signedIn() { return request.auth != null; }\n    function uid() { return request.auth.uid; }\n    function shootData(sid) { return get(/databases/$(database)/documents/shoots/$(sid)).data; }\n    function shootIsProjectLevel(s) { return signedIn() && s.get('projectOwnerId', '') == uid(); }\n    function shootReadable(sid) { let s = shootData(sid); return shootIsProjectLevel(s) || (signedIn() && s.get('archived', false) == false); }\n    match /shoots/{shootId} {\n      allow read: if shootReadable(shootId);\n      allow write: if false;\n    }\n  }\n}\n",
    );
    writeFileSync(
      join(root, 'src', 'queries.ts'),
      "import { collection, getFirestore, onSnapshot, query, where } from 'firebase/firestore';\n" +
        "const db = getFirestore();\n" +
        "// viewer list: satisfies the archived branch\n" +
        "onSnapshot(query(collection(db, 'shoots'), where('archived', '==', false)), () => {});\n" +
        "// bare list: satisfies no branch\n" +
        "onSnapshot(query(collection(db, 'shoots')), () => {});\n",
    );
  });
  const mismatches = findings.filter((finding) => finding.source.ruleId === 'rule-query-mismatch');
  assert.equal(mismatches.length, 1, 'expected only the bare list to mismatch');
  assert.ok(String(mismatches[0]?.message).includes('archived'));
  assert.ok(String(mismatches[0]?.message).includes('projectOwnerId'), 'message names the alternatives');
});

test('firebase provider checks every per-bucket storage rules file', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(join(root, 'storage.rules'), 'service firebase.storage { match /b/{bucket}/o { match /{allPaths=**} { allow read: if request.auth != null; allow write: if false; } } }');
    writeFileSync(join(root, 'storage.rvmedia.rules'), 'service firebase.storage { match /b/{bucket}/o { match /{allPaths=**} { allow read, write: if true; } } }');
  });
  const open = findings.filter((finding) => finding.source.ruleId === 'open-rules');
  assert.equal(open.length, 1, 'expected one open-rules finding');
  assert.equal(open[0]?.file, 'storage.rvmedia.rules', 'the open bucket is named');
  assert.equal(open[0]?.severity, 'critical');
});

test('firebase provider flags client-side Storage usage with no rules in repo', async () => {
  const findings = await runFixture((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { firebase: '^12' } }));
    writeFileSync(
      join(root, 'src', 'media.ts'),
      "import { getStorage, ref, uploadBytes } from 'firebase/storage';\nexport const store = getStorage();\n",
    );
  });
  const missing = findings.filter((finding) => finding.source.ruleId === 'missing-rules' && finding.file === 'storage.rules');
  assert.equal(missing.length, 1, 'expected a storage missing-rules finding');
  assert.equal(missing[0]?.severity, 'medium');
  assert.equal(missing[0]?.teardownId, 'TD-008');
});

test('scanFirestoreQueries does not bleed into the next statement', () => {
  const queries = scanFirestoreQueries(
    "getDocs(collection(db, `shoots/${id}/shotlist`)),\n  getDoc(doc(db, 'projects', pid)),\n];\n",
  );
  const paths = queries.map((q) => q.pathKey);
  assert.ok(paths.includes('shoots/shotlist'), `expected the shotlist path, got ${JSON.stringify(paths)}`);
  assert.ok(!paths.some((p) => p.includes('projects')), 'next statement strings must not leak in');
});

test('a plain match does not govern subcollections; a **-rule does', () => {
  const scope = parseRulesScope(`
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function uid() { return request.auth.uid; }
    match /shoots/{shootId} {
      allow read: if resource.data.get('ownerUid', '') == uid();
    }
    match /tenants/{tenantId}/{d=**} {
      allow read: if resource.data.get('ownerUid', '') == uid();
    }
  }
}
`);
  // `shoots/{id}/logs` is a deeper path - the shoots rule (no **) does not apply.
  assert.equal(matchScopeRule(scope, 'shoots/x/logs'), null);
  assert.equal(matchScopeRule(scope, 'shoots'), scope.get('shoots'));
  // `tenants/...` recurses via {d=**}.
  const tenantsRule = matchScopeRule(scope, 'tenants/x/anything/deep');
  assert.equal(tenantsRule, scope.get('tenants'));
});

test('firebase provider ignores denied-shape test files in the cross-check', async () => {
  const findings = await runFixture((root) => {
    mkdirSync(join(root, 'scripts'), { recursive: true });
    writeFileSync(
      join(root, 'firestore.rules'),
      "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    function uid() { return request.auth.uid; }\n    match /rvFilms/{filmId} {\n      allow read: if resource.data.get('ownerUid', '') == uid();\n    }\n  }\n}\n",
    );
    // A rules-test style file deliberately runs the DENIED query shape.
    writeFileSync(
      join(root, 'scripts', 'rules-test.mjs'),
      "import { collection, getFirestore, getDocs, query } from 'firebase/firestore';\nconst db = getFirestore();\nawait assertFails(getDocs(query(collection(db, 'rvFilms'))));\n",
    );
  });
  const mismatches = findings.filter((finding) => finding.source.ruleId === 'rule-query-mismatch');
  assert.equal(mismatches.length, 0, 'test-file queries are deliberate negative assertions');
});

test('parseRulesScope records rules-denied writes per match block', () => {
  const scope = parseRulesScope(`
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() { return request.auth != null; }
    match /rvLedger/{entryId} {
      allow read: if signedIn();
      allow write: if false;
    }
    match /rvOrders/{orderId} {
      allow read: if signedIn();
    }
    match /rvProfiles/{uid} {
      allow read: if signedIn();
      allow create: if signedIn() && uid == request.auth.uid;
    }
  }
}
`);
  assert.equal(scope.get('rvLedger')?.writesDenied, true, 'if false denies');
  assert.equal(scope.get('rvOrders')?.writesDenied, true, 'no write rule = deny by default');
  assert.equal(scope.get('rvProfiles')?.writesDenied, false, 'real create allow');
});

test('scanFirestoreWrites finds write paths and skips reads', () => {
  const writes = scanFirestoreWrites(
    "setDoc(doc(getDb(), 'rvLedger', entryId), data);\n" +
      "await updateDoc(doc(getDb(), 'rvOrders', oid), { status: 'x' });\n" +
      "await addDoc(collection(getDb(), 'rvProfiles'), data);\n" +
      "deleteDoc(doc(getDb(), `rvTickets/${id}`), x);\n" +
      "getDoc(doc(getDb(), 'rvFilms', fid));\n",
  );
  const paths = writes.map((w) => w.pathKey);
  assert.ok(paths.includes('rvLedger'), `rvLedger collection path, got ${JSON.stringify(paths)}`);
  assert.ok(paths.includes('rvOrders'));
  assert.ok(paths.includes('rvProfiles'));
  assert.ok(paths.includes('rvTickets'), 'template doc id normalized away');
  assert.equal(paths.filter((p) => p.includes('rvFilms')).length, 0, 'reads are not writes');
});

test('firebase provider flags client writes to rules-denied collections', async () => {
  const findings = await runFixture((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    mkdirSync(join(root, 'functions'), { recursive: true });
    writeFileSync(
      join(root, 'firestore.rules'),
      "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    function signedIn() { return request.auth != null; }\n    match /rvLedger/{entryId} {\n      allow read: if signedIn();\n      allow write: if false;\n    }\n    match /rvProfiles/{uid} {\n      allow read: if signedIn();\n      allow create: if signedIn();\n    }\n  }\n}\n",
    );
    writeFileSync(
      join(root, 'src', 'client.ts'),
      "import { doc, getFirestore, setDoc } from 'firebase/firestore';\n" +
        "const db = getFirestore();\n" +
        "setDoc(doc(db, 'rvLedger', 'l1'), { amount: 1 });\n" +
        "setDoc(doc(db, 'rvProfiles', 'p1'), { name: 'x' });\n",
    );
    // Server-side Admin SDK writes bypass rules - never flagged.
    writeFileSync(
      join(root, 'functions', 'index.ts'),
      "import { getFirestore } from 'firebase-admin/firestore';\n" +
        "export const fn = () => getFirestore().collection('rvLedger').doc('l1').set({ amount: 1 });\n",
    );
  });
  const denied = findings.filter((finding) => finding.source.ruleId === 'write-denied');
  assert.equal(denied.length, 1, 'only the rvLedger client write is denied');
  assert.equal(denied[0]?.file, 'src/client.ts');
  assert.equal(denied[0]?.severity, 'high');
  assert.equal(denied[0]?.teardownId, 'TD-008');
  assert.ok(String(denied[0]?.message).includes('rvLedger'));
});
