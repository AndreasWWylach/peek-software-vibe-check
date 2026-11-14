// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the tests provider (QA-pillar test signal).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hasAssertions, testsProvider } from '../src/providers/tests.mjs';

test('hasAssertions recognizes common assertion shapes and rejects stubs', () => {
  assert.equal(hasAssertions("expect(add(1, 2)).toBe(3);"), true);
  assert.equal(hasAssertions('assert.equal(add(1, 2), 3);'), true);
  assert.equal(hasAssertions('assert add(1, 2) == 3'), true); // Python bare assert
  assert.equal(hasAssertions('assertEquals(3, add(1, 2));'), true);
  assert.equal(hasAssertions('expect(fn).to.throw(Error);'), true);
  assert.equal(hasAssertions('$this->assertSame($a, $b);'), true);
  assert.equal(hasAssertions('it("runs", () => { add(1, 2); });'), false); // no assertion
  assert.equal(hasAssertions('test("x", () => console.log("hi"));'), false);
});

test('tests provider: reports "no tests" when the repo has none', async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-tests-'));
  try {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src', 'app.js'), 'export const add = (a, b) => a + b;\n');
    const findings = await testsProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'src')], log: () => {} }),
    );
    assert.equal(findings.length, 1);
    assert.equal(findings[0].source.ruleId, 'no-tests');
    assert.equal(findings[0].kind, 'hygiene');
    assert.equal(findings[0].pillar, 'qa');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('tests provider: flags assertion-less test files as TD-017, ignores real assertions', async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-tests-'));
  try {
    mkdirSync(join(root, 'src', '__tests__'), { recursive: true });
    writeFileSync(join(root, 'src', '__tests__', 'real.test.js'), 'test("x", () => { expect(1).toBe(1); });\n');
    writeFileSync(join(root, 'src', '__tests__', 'stub.test.js'), 'test("x", () => { doThing(); });\n');
    // A helper/fake under a test/ dir is NOT a test case — must not be flagged.
    writeFileSync(join(root, 'src', '__tests__', 'helpers.js'), 'export const fake = () => ({ get: () => 1 });\n');
    const findings = await testsProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'src')], log: () => {} }),
    );
    assert.equal(findings.length, 1);
    assert.equal(findings[0].teardownId, 'TD-017');
    assert.equal(findings[0].file, 'src/__tests__/stub.test.js');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
