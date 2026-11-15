// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for scan-time stack detection.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { detectStack, findRulesFile } from '../src/stack.mjs';

test('detectStack reads firebase.json, package.json deps and rules files', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-check-stack-'));
  try {
    writeFileSync(join(root, 'firebase.json'), '{}');
    mkdirSync(join(root, 'functions'), { recursive: true });
    writeFileSync(
      join(root, 'functions', 'package.json'),
      JSON.stringify({ dependencies: { 'firebase-admin': '^12', 'firebase-functions': '^5', stripe: '^18' } }),
    );
    mkdirSync(join(root, 'frontend'), { recursive: true });
    writeFileSync(
      join(root, 'frontend', 'package.json'),
      JSON.stringify({ dependencies: { react: '^19', firebase: '^12' } }),
    );
    writeFileSync(join(root, 'firestore.rules'), 'rules_version = "2";');

    const stack = detectStack(root, [root]);
    assert.equal(stack.firebase, true);
    assert.equal(stack.firestore, true);
    assert.equal(stack.cloudFunctions, true);
    assert.equal(stack.stripe, true);
    assert.equal(stack.react, true);
    assert.equal(stack.express, undefined);
    assert.equal(findRulesFile(root, [root], 'firestore.rules'), 'firestore.rules');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('detectStack ignores node_modules and tolerates missing files', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-check-stack-'));
  try {
    mkdirSync(join(root, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(join(root, 'node_modules', 'pkg', 'package.json'), JSON.stringify({ dependencies: { express: '^5' } }));
    assert.deepEqual(detectStack(root, [root]), {});
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('findRulesFile sees rules at the repo root even when targets exclude it', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-check-stack-'));
  try {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src', 'main.js'), 'const x = 1;\n');
    writeFileSync(join(root, 'firestore.rules'), 'rules_version = "2";\nservice cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if request.auth != null; } } }\n');
    writeFileSync(join(root, 'storage.rules'), 'rules_version = "2";\n');

    // Targets exclude the repo root — the rules files must still be found.
    assert.equal(findRulesFile(root, [join(root, 'src')], 'firestore.rules'), 'firestore.rules');
    assert.equal(findRulesFile(root, [join(root, 'src')], 'storage.rules'), 'storage.rules');
    const stack = detectStack(root, [join(root, 'src')]);
    assert.equal(stack.firestore, true);
    assert.equal(stack.storage, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
