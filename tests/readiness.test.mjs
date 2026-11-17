// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the go-live readiness verdict.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { computeReadiness } from '../src/readiness.mjs';
import { detectAppCheckOff } from '../src/stack.mjs';

const CLEAN_CI = { noPipeline: false, noTests: false, noCoverage: false };

test('computeReadiness: clean app → go', () => {
  const r = computeReadiness({ deps: { critical: 0, high: 0 }, ci: CLEAN_CI, appCheckOff: null, disabledCount: 0 });
  assert.equal(r.status, 'go');
  assert.deepEqual(r.conditions, []);
});

test('computeReadiness: high CVEs + no coverage → conditional', () => {
  const r = computeReadiness({ deps: { critical: 0, high: 3 }, ci: { ...CLEAN_CI, noCoverage: true }, appCheckOff: null, disabledCount: 0 });
  assert.equal(r.status, 'conditional');
  assert.ok(r.conditions.some((c) => c.includes('3 high')));
  assert.ok(r.conditions.some((c) => c.includes('coverage')));
});

test('computeReadiness: critical CVE → no-go', () => {
  const r = computeReadiness({ deps: { critical: 2, high: 0 }, ci: CLEAN_CI, appCheckOff: null, disabledCount: 0 });
  assert.equal(r.status, 'no-go');
  assert.ok(r.conditions.some((c) => c.includes('2 critical')));
});

test('computeReadiness: App Check off + disabled checks are conditions', () => {
  const r = computeReadiness({ deps: { critical: 0, high: 0 }, ci: CLEAN_CI, appCheckOff: true, disabledCount: 1 });
  assert.equal(r.status, 'conditional');
  assert.ok(r.conditions.some((c) => c.includes('App Check')));
  assert.ok(r.conditions.some((c) => c.includes('1 check')));
});

test('computeReadiness: CI precedence — noPipeline beats noTests beats noCoverage', () => {
  const r = computeReadiness({ deps: { critical: 0, high: 0 }, ci: { noPipeline: true, noTests: true, noCoverage: true }, appCheckOff: null, disabledCount: 0 });
  assert.deepEqual(r.conditions, ['No CI pipeline — tests and checks are not enforced on every change.']);
});

test('detectAppCheckOff: null off-app, off when unwired, on when enforceAppCheck: true', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-appcheck-'));
  try {
    assert.equal(detectAppCheckOff(root, {}), null);
    assert.equal(detectAppCheckOff(root, { cloudFunctions: true }), true); // no functions dir → off
    mkdirSync(join(root, 'functions'), { recursive: true });
    writeFileSync(join(root, 'functions', 'index.js'), 'exports.x = 1;\n');
    assert.equal(detectAppCheckOff(root, { cloudFunctions: true }), true); // no App Check wiring
    writeFileSync(join(root, 'functions', 'index.js'), "const APP_CHECK_ENFORCE = /^(1|true)$/i.test(process.env.APP_CHECK_ENFORCE || '');\n");
    assert.equal(detectAppCheckOff(root, { cloudFunctions: true }), true); // env flag, default off
    writeFileSync(join(root, 'functions', 'index.js'), 'enforceAppCheck: true\n');
    assert.equal(detectAppCheckOff(root, { cloudFunctions: true }), false); // literal true → enforced
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
