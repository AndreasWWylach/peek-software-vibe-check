// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the PHPStan provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { phpstanProvider, phpstanIdentifier, parsePhpstanJson } from '../src/providers/phpstan.mjs';

test('phpstanIdentifier passes through the identifier field, else derives it', () => {
  assert.equal(phpstanIdentifier({ identifier: 'method.notFound', message: 'x' }), 'method.notFound');
  assert.equal(phpstanIdentifier({ message: 'Call to an undefined method Foo::bar().' }), 'method.notFound');
  assert.equal(phpstanIdentifier({ message: 'Access to an undefined property Foo::$bar.' }), 'property.notFound');
  assert.equal(phpstanIdentifier({ message: 'Class Bar not found.' }), 'class.notFound');
});

test('parsePhpstanJson keeps the hallucination class and drops style/type noise', () => {
  const stdout = JSON.stringify({
    totals: { errors: 3, file_errors: 3 },
    files: {
      '/repo/app.php': {
        errors: 3,
        messages: [
          { message: 'Call to an undefined method Order::calculateTotl().', line: 8, identifier: 'method.notFound' },
          { message: 'Instantiated class NonExistentClass not found.', line: 11, identifier: 'class.notFound' },
          { message: 'Class Foo is neither abstract nor final.', line: 3, identifier: 'ergebnis.final' },
          { message: 'Parameter #1 $x expects string, int given.', line: 5, identifier: 'argument.type' },
        ],
      },
    },
  });

  const findings = parsePhpstanJson(stdout, '/repo');
  const ids = findings.map((f) => f.source.ruleId);
  assert.deepEqual(ids, ['method.notFound', 'class.notFound']);
  for (const f of findings) {
    assert.equal(f.kind, 'hygiene');
    assert.equal(f.pillar, 'qa');
    assert.equal(f.advisory, true);
    assert.equal(f.teardownId, null);
  }
  assert.equal(findings[0].file, 'app.php');
  assert.equal(findings[0].line, 8);
});

test('phpstan applicable gates on the php language', () => {
  /** @type {import('../src/types.mjs').ScanConfig} */
  const phpConfig = { version: 1, engine: '>=0.1.0', targets: ['src/'], exclude: [], languages: ['php'], enabledRules: [], ruleParams: {}, scoring: { weights: { security: 1, runtime: 1, architecture: 1, qa: 1 } }, quiz: undefined };
  /** @type {import('../src/types.mjs').ScanConfig} */
  const jsConfig = { version: 1, engine: '>=0.1.0', targets: ['src/'], exclude: [], languages: ['javascript'], enabledRules: [], ruleParams: {}, scoring: { weights: { security: 1, runtime: 1, architecture: 1, qa: 1 } }, quiz: undefined };
  assert.equal(phpstanProvider.applicable(phpConfig), true);
  assert.equal(phpstanProvider.applicable(jsConfig), false);
});
