// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for the wildcard-CORS provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { corsProvider } from '../src/providers/cors.mjs';

/** Build a temp repo with the given files and run the provider against it.
 * @param {Record<string, string>} files — path → content (dirs created as needed).
 * @returns {Promise<import('../src/types.mjs').Finding[]>}
 */
async function run(files) {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-cors-'));
  try {
    for (const [path, content] of Object.entries(files)) {
      const abs = join(dir, path);
      mkdirSync(join(abs, '..'), { recursive: true });
      writeFileSync(abs, content, 'utf8');
    }
    return await corsProvider.run(
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

test('corsProvider: cors({ origin: "*" }) in an Express app is an advisory', async () => {
  const findings = await run({
    'package.json': PKG({ express: '^4', cors: '^2' }),
    'src/app.ts': "app.use(cors({ origin: '*' }));",
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].advisory, true);
  assert.equal(findings[0].severity, 'medium');
  assert.equal(findings[0].source.provider, 'cors');
  assert.match(findings[0].message ?? '', /allows every origin/);
});

test('corsProvider: wildcard + credentials mentions the broken combination', async () => {
  const findings = await run({
    'package.json': PKG({ express: '^4', cors: '^2' }),
    'src/app.ts': "app.use(cors({ origin: '*', credentials: true }));",
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].message ?? '', /browsers reject/);
});

test('corsProvider: a restricted origin stays silent', async () => {
  const findings = await run({
    'package.json': PKG({ express: '^4', cors: '^2' }),
    'src/app.ts': "app.use(cors({ origin: 'https://app.example.com' }));",
  });
  assert.deepEqual(findings, []);
});

test('corsProvider: FastAPI allow_origins=["*"] fires, allowlist stays silent', async () => {
  const findings = await run({
    'requirements.txt': 'fastapi==0.110\n',
    'src/main.py': 'app.add_middleware(CORSMiddleware, allow_origins=["*"])',
  });
  assert.equal(findings.length, 1);

  const silent = await run({
    'requirements.txt': 'fastapi==0.110\n',
    'src/main.py': 'app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"])',
  });
  assert.deepEqual(silent, []);
});

test('corsProvider: PHP header wildcard fires', async () => {
  const findings = await run({
    'composer.json': JSON.stringify({ require: {} }),
    'src/index.php': "<?php header('Access-Control-Allow-Origin: *');",
  });
  assert.equal(findings.length, 1);
});

test('corsProvider: nginx add_header wildcard fires even without a framework', async () => {
  const findings = await run({
    'nginx.conf': 'server { add_header Access-Control-Allow-Origin * always; }',
    'src/index.html': '<html></html>',
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].message ?? '', /nginx.conf/);
});

test('corsProvider: no server framework and no hosting config is not applicable', async () => {
  const findings = await run({
    'src/util.ts': "const x = { origin: '*', something: true };",
  });
  assert.deepEqual(findings, []);
});
