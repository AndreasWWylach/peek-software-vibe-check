// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the dependency-hygiene provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { depsProvider, isFloatingNpm, isFloatingComposer, isFloatingRequirement, isComposerPlatformPackage } from '../src/providers/deps.mjs';

test('isFloatingNpm flags unbounded versions, accepts caret/tilde', () => {
  assert.equal(isFloatingNpm('*'), true);
  assert.equal(isFloatingNpm('latest'), true);
  assert.equal(isFloatingNpm('>=1.2.3'), true);
  assert.equal(isFloatingNpm('file:../pkg'), true);
  assert.equal(isFloatingNpm('git+https://github.com/a/b.git'), true);
  assert.equal(isFloatingNpm('^1.2.3'), false);
  assert.equal(isFloatingNpm('~1.2.3'), false);
  assert.equal(isFloatingNpm('1.2.3'), false);
  assert.equal(isFloatingNpm('>=1.2.3 <2.0.0'), false);
});

test('isFloatingComposer flags star/branch/unbounded, accepts caret/tilde', () => {
  assert.equal(isFloatingComposer('*'), true);
  assert.equal(isFloatingComposer('dev-master'), true);
  assert.equal(isFloatingComposer('>=1.0'), true);
  assert.equal(isFloatingComposer('^1.0'), false);
  assert.equal(isFloatingComposer('~1.0'), false);
  assert.equal(isFloatingComposer('>=1.0 <2.0'), false);
});

test('isFloatingRequirement flags bare/unbounded specs, accepts pins', () => {
  assert.equal(isFloatingRequirement('flask'), true);
  assert.equal(isFloatingRequirement('flask>=2.0'), true);
  assert.equal(isFloatingRequirement('flask*'), true);
  assert.equal(isFloatingRequirement('flask==2.0'), false);
  assert.equal(isFloatingRequirement('flask~=2.0'), false);
  assert.equal(isFloatingRequirement('flask>=2.0,<3'), false);
});

test('isComposerPlatformPackage recognizes php/ext/lib platform requirements', () => {
  assert.equal(isComposerPlatformPackage('php'), true);
  assert.equal(isComposerPlatformPackage('ext-json'), true);
  assert.equal(isComposerPlatformPackage('lib-icu'), true);
  assert.equal(isComposerPlatformPackage('composer-plugin-api'), true);
  assert.equal(isComposerPlatformPackage('pimcore/pimcore'), false);
  assert.equal(isComposerPlatformPackage('symfony/console'), false);
});

test('deps provider: skips composer platform requirements', async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-deps-'));
  try {
    writeFileSync(
      join(root, 'composer.json'),
      JSON.stringify({ require: { php: '>=8.1', 'ext-json': '*', 'pimcore/pimcore': '*', 'symfony/console': '^6.2' } }),
    );
    writeFileSync(join(root, 'composer.lock'), '{}');

    const findings = await depsProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'composer.json')], log: () => {} }),
    );
    const floating = findings.filter((f) => f.source.ruleId === 'floating-version');
    // Only pimcore/pimcore (`*`) is flagged; php/ext-json platform + ^6.2 are not.
    assert.equal(floating.length, 1);
    assert.match(floating[0].title, /pimcore\/pimcore/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('deps provider: flags missing lockfile + floating versions', async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-deps-'));
  try {
    mkdirSync(join(root, 'src'), { recursive: true });
    // package.json with no lockfile and a floating dep.
    writeFileSync(
      join(root, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { express: '^4.18.0', lodash: '*' } }, null, 2),
    );
    // requirements.txt with one pinned + two floating lines.
    writeFileSync(
      join(root, 'src', 'requirements.txt'),
      'flask==2.3.0\nflask-cors\nrequests>=2.31\n',
    );

    const findings = await depsProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'src'), join(root, 'package.json')], log: () => {} }),
    );

    const ruleIds = findings.map((f) => f.source.ruleId).sort();
    assert.deepEqual(ruleIds, ['floating-version', 'floating-version', 'floating-version', 'no-lockfile']);

    const noLockfile = findings.find((f) => f.source.ruleId === 'no-lockfile');
    assert.equal(noLockfile?.file, 'package.json');
    assert.equal(noLockfile?.pillar, 'runtime');
    assert.equal(noLockfile?.advisory, undefined); // missing lockfile is a scored defect

    // The floating lodash (*) is caught; express ^4.18.0 is not.
    const floating = findings.filter((f) => f.source.ruleId === 'floating-version');
    // Floating versions are advisories: reported, but not scored.
    assert.ok(floating.every((f) => f.advisory === true));
    const titles = floating.map((f) => f.title).join(' ');
    assert.match(titles, /lodash/);
    assert.doesNotMatch(titles, /express/);
    assert.match(titles, /flask-cors/);
    assert.match(titles, /requests/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('deps provider: lockfile in root satisfies workspace manifests', async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-deps-'));
  try {
    mkdirSync(join(root, 'packages', 'a'), { recursive: true });
    writeFileSync(join(root, 'packages', 'a', 'package.json'), JSON.stringify({ name: 'a', dependencies: { lodash: '^4' } }));
    writeFileSync(join(root, 'package-lock.json'), '{}');

    const findings = await depsProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'packages')], log: () => {} }),
    );
    assert.equal(findings.some((f) => f.source.ruleId === 'no-lockfile'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
