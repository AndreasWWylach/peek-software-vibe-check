// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for vendored Semgrep PHP pack classification.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyVendoredFile, normalizeCheckId } from '../src/providers/semgrep.mjs';

test('normalizeCheckId strips the machine path at the rules/ root', () => {
  assert.equal(
    normalizeCheckId('var.projects.peek-software-vibe-check.rules.vendored.php.lang.security.weak-crypto'),
    'vendored.php.lang.security.weak-crypto',
  );
  assert.equal(
    normalizeCheckId('home.user.code.vibe-check.rules.peek.TD-033.typescript'),
    'peek.TD-033.typescript',
  );
  // Ids without the rules/ marker pass through unchanged.
  assert.equal(normalizeCheckId('some.other.rule'), 'some.other.rule');
});

test('classifyVendoredFile promotes only taint-proven SQLi/command-injection rules', () => {
  const root = '/repo/rules/vendored/php/';
  assert.equal(classifyVendoredFile(`${root}lang/security/injection/tainted-sql-string.yaml`), 'TD-033');
  assert.equal(classifyVendoredFile(`${root}laravel/laravel-sql-injection.yaml`), 'TD-033');
  assert.equal(classifyVendoredFile(`${root}lang/security/injection/tainted-exec.yaml`), 'TD-042');
  // Presence-of-sink rules stay advisories (no TD).
  assert.equal(classifyVendoredFile(`${root}lang/security/exec-use.yaml`), null);
  assert.equal(classifyVendoredFile(`${root}lang/security/weak-crypto.yaml`), null);
  assert.equal(classifyVendoredFile(`${root}wordpress/audit/wp-sql-injection-audit.yaml`), null);
});
