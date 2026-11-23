// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the onboarding module (pure logic only — no
 * installs, no prompts). The installer is the trust surface: these pin the
 * version parsing, status classification, and step planning.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  TOOLS,
  extractVersionTriple,
  compareSemver,
  checkTool,
  planSteps,
  commandFor,
  detectStackNeeds,
  toolNeed,
} from '../src/onboarding.mjs';

test('extractVersionTriple parses the tool version formats we shell out to', () => {
  assert.deepEqual(extractVersionTriple('v20.20.2'), [20, 20, 2]);
  assert.deepEqual(extractVersionTriple('scc version 3.5.0'), [3, 5, 0]);
  assert.deepEqual(extractVersionTriple('gitleaks version 8.30.1'), [8, 30, 1]);
  assert.deepEqual(extractVersionTriple('osv-scanner version: 2.7.1'), [2, 7, 1]);
  assert.deepEqual(extractVersionTriple('no version here'), null);
});

test('compareSemver orders triples correctly', () => {
  assert.ok(compareSemver([20, 0, 0], [20, 1, 0]) < 0);
  assert.ok(compareSemver([9, 0, 0], [8, 99, 99]) > 0);
  assert.equal(compareSemver([3, 5, 0], [3, 5, 0]), 0);
});

test('checkTool classifies missing / outdated / ok', () => {
  const tool = TOOLS.find((t) => t.id === 'node');
  assert.ok(tool);
  assert.equal(checkTool(tool, null).status, 'missing');
  assert.equal(checkTool(tool, [20, 0, 0]).status, 'outdated');
  assert.equal(checkTool(tool, [22, 0, 0]).status, 'ok');
  assert.equal(checkTool(tool, [22, 1, 0]).version, '22.1.0');
});

test('planSteps puts node first and honors --skip', () => {
  const results = TOOLS.map((tool) => checkTool(tool, null));
  const steps = planSteps(results, { skip: ['eslint', 'madge'] });
  assert.equal(steps[0].tool.id, 'node');
  assert.ok(!steps.some((step) => step.tool.id === 'eslint' || step.tool.id === 'madge'));
  assert.ok(steps.some((step) => step.tool.id === 'semgrep'));
});

test('planSteps is empty when everything is ok', () => {
  const results = TOOLS.map((tool) => checkTool(tool, tool.minVersion));
  assert.deepEqual(planSteps(results), []);
});

test('registry integrity: every tool is installable and transparent', () => {
  const ids = new Set(TOOLS.map((tool) => tool.id));
  assert.equal(ids.size, TOOLS.length, 'tool ids must be unique');
  for (const tool of TOOLS) {
    assert.ok(tool.role, `${tool.id} needs a role`);
    assert.ok(tool.install.source, `${tool.id} needs an official source`);
    assert.ok(Array.isArray(tool.minVersion) && tool.minVersion.length === 3, `${tool.id} needs a semver triple`);
    if (tool.install.kind === 'download') {
      assert.ok(tool.install.url && tool.install.sha256, `${tool.id} download needs url + sha256`);
    } else if (tool.install.kind === 'command') {
      assert.ok(tool.install.commands && Object.keys(tool.install.commands).length > 0, `${tool.id} needs a command`);
    }
  }
});

test('commandFor falls back to the default command', () => {
  const madge = TOOLS.find((tool) => tool.id === 'madge');
  assert.ok(madge);
  assert.equal(commandFor(madge.install, 'brew'), 'npm install -g madge');
  assert.equal(commandFor(madge.install, null), 'npm install -g madge');
});

test('semgrep install tries pipx, then pip, then bootstraps pip via get-pip.py', () => {
  const semgrep = TOOLS.find((tool) => tool.id === 'semgrep');
  assert.ok(semgrep);
  const command = commandFor(semgrep.install, null);
  assert.ok(command.includes('pipx install semgrep'), 'pipx path stays first');
  assert.ok(command.includes('pip3 install --user semgrep'), 'pip3 fallback present');
  assert.ok(command.includes('python3 -m pip install --user semgrep'), 'python3 -m pip fallback present');
  assert.ok(command.includes('bootstrap.pypa.io/get-pip.py'), 'bootstraps pip via the official get-pip.py');
  assert.ok(command.includes('exit 1'), 'fails loudly when no Python/pip exists');
});

test('detectStackNeeds sees the JS/Docker stack of a repo', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-stack-'));
  try {
    writeFileSync(join(dir, 'package.json'), '{}');
    mkdirSync(join(dir, 'deploy'));
    writeFileSync(join(dir, 'deploy', 'Dockerfile'), 'FROM node:22');
    const stack = detectStackNeeds(dir);
    assert.equal(stack.anyStack, true);
    assert.equal(stack.js, true);
    assert.equal(stack.docker, true);
    assert.equal(stack.iac, true);
    assert.equal(stack.python, false);
    assert.equal(stack.php, false);
    assert.equal(stack.go, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('detectStackNeeds reports anyStack=false for an empty directory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-stack-'));
  try {
    assert.equal(detectStackNeeds(dir).anyStack, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('toolNeed maps tools to stack markers', () => {
  const empty = detectStackNeeds('/nonexistent');
  /** @type {import('../src/onboarding.mjs').StackNeeds} */
  const jsStack = { ...empty, anyStack: true, js: true };
  /** @type {import('../src/onboarding.mjs').StackNeeds} */
  const pyStack = { ...empty, anyStack: true, python: true };
  /** @type {import('../src/onboarding.mjs').StackNeeds} */
  const phpStack = { ...empty, anyStack: true, php: true };
  /** @type {import('../src/onboarding.mjs').StackNeeds} */
  const goStack = { ...empty, anyStack: true, go: true };

  assert.equal(toolNeed('eslint', jsStack).needed, true);
  assert.equal(toolNeed('madge', jsStack).needed, true);
  assert.equal(toolNeed('bandit', pyStack).needed, true);
  assert.equal(toolNeed('phpstan', phpStack).needed, true);
  assert.equal(toolNeed('gosec', goStack).needed, true);
  assert.equal(toolNeed('hadolint', { ...jsStack, docker: true }).needed, true);
  assert.equal(toolNeed('checkov', { ...jsStack, iac: true }).needed, true);

  assert.equal(toolNeed('eslint', pyStack).needed, false); // no JS
  assert.equal(toolNeed('bandit', jsStack).needed, false); // no Python
  assert.equal(toolNeed('phpstan', jsStack).needed, false); // no PHP
  assert.equal(toolNeed('gosec', jsStack).needed, false); // no Go
  assert.equal(toolNeed('hadolint', jsStack).needed, false); // no Dockerfile

  // The engine core is always needed.
  for (const id of ['node', 'semgrep', 'osv-scanner', 'scc', 'gitleaks']) {
    assert.equal(toolNeed(id, jsStack).needed, true, id);
  }
});
