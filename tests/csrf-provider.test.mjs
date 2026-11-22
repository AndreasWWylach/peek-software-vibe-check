// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for the CSRF protection provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { csrfProvider } from '../src/providers/csrf.mjs';

/** Build a temp repo with the given files and run the provider against it.
 * @param {Record<string, string>} files — path → content (dirs created as needed).
 * @returns {Promise<import('../src/types.mjs').Finding[]>}
 */
async function run(files) {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-csrf-'));
  try {
    for (const [path, content] of Object.entries(files)) {
      const abs = join(dir, path);
      mkdirSync(join(abs, '..'), { recursive: true });
      writeFileSync(abs, content, 'utf8');
    }
    return await csrfProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: dir, targets: [join(dir, 'src')], stack: {}, log: () => {} }),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Build a package.json with the given dependency names.
 * @param {Record<string, string>} deps
 * @returns {string}
 */
const PKG = (deps) => JSON.stringify({ name: 'app', dependencies: deps });

test('csrfProvider: express-session without protection is an advisory', async () => {
  const findings = await run({
    'package.json': PKG({ express: '^4', 'express-session': '^1' }),
    'src/app.ts': "app.use(session({ secret: 'x' }));\napp.post('/pay', handler);",
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].advisory, true);
  assert.equal(findings[0].severity, 'medium');
  assert.equal(findings[0].pillar, 'security');
  assert.match(findings[0].message ?? '', /express-session/);
});

test('csrfProvider: csurf dependency silences the finding', async () => {
  const findings = await run({
    'package.json': PKG({ express: '^4', 'express-session': '^1', csurf: '^1' }),
    'src/app.ts': "app.use(csrf());\napp.post('/pay', handler);",
  });
  assert.deepEqual(findings, []);
});

test('csrfProvider: SameSite evidence silences the finding', async () => {
  const findings = await run({
    'package.json': PKG({ express: '^4', 'express-session': '^1' }),
    'src/app.ts': "app.use(session({ secret: 'x', cookie: { sameSite: 'strict' } }));",
  });
  assert.deepEqual(findings, []);
});

test('csrfProvider: token-auth only (no cookie libs) is not applicable', async () => {
  const findings = await run({
    'package.json': PKG({ express: '^4', jsonwebtoken: '^9' }),
    'src/app.ts': "app.post('/pay', jwtHandler);",
  });
  assert.deepEqual(findings, []);
});

test('csrfProvider: Flask without Flask-WTF is flagged', async () => {
  const findings = await run({
    'requirements.txt': 'flask==3.0.0\n',
    'src/app.py': "from flask import Flask\napp = Flask(__name__)\n",
  });
  assert.equal(findings.length, 1);
});

test('csrfProvider: Flask with Flask-WTF is silent', async () => {
  const findings = await run({
    'requirements.txt': 'flask==3.0.0\nflask-wtf==1.2.0\n',
    'src/app.py': "from flask_wtf import CSRFProtect\nCSRFProtect(app)\n",
  });
  assert.deepEqual(findings, []);
});

test('csrfProvider: Django is silent (CSRF middleware on by default)', async () => {
  const findings = await run({
    'requirements.txt': 'django==5.0\n',
    'src/views.py': 'from django.http import HttpResponse\n',
  });
  assert.deepEqual(findings, []);
});

test('csrfProvider: PHP session_start without tokens is flagged', async () => {
  const findings = await run({
    'composer.json': JSON.stringify({ require: {} }),
    'src/index.php': "<?php session_start(); $_SESSION['user'] = 1;",
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].message ?? '', /session_start/);
});

test('csrfProvider: Symfony security-csrf is silent', async () => {
  const findings = await run({
    'composer.json': JSON.stringify({ require: { 'symfony/security-csrf': '^7' } }),
    'src/index.php': "<?php session_start();",
  });
  assert.deepEqual(findings, []);
});

test('csrfProvider: Laravel is silent (built-in CSRF)', async () => {
  const findings = await run({
    'composer.json': JSON.stringify({ require: { 'laravel/framework': '^11' } }),
    'src/web.php': "<?php Route::post('/pay', fn () => 'ok');",
  });
  assert.deepEqual(findings, []);
});

test('csrfProvider: transitive security-csrf in composer.lock is silent', async () => {
  const findings = await run({
    'composer.json': JSON.stringify({ require: { 'pimcore/pimcore': '^11' } }),
    'composer.lock': JSON.stringify({ packages: [{ name: 'symfony/security-csrf', version: 'v7.0' }] }),
    'src/index.php': "<?php session_start();",
  });
  assert.deepEqual(findings, []);
});
