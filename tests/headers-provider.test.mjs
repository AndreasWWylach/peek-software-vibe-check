// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the security-headers provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { headersProvider } from '../src/providers/headers.mjs';

/**
 * @param {Record<string, string>} files — repo-relative path → content.
 * @returns {Promise<import('../src/types.mjs').Finding[]>}
 */
async function scan(files) {
  const root = mkdtempSync(join(tmpdir(), 'vibe-headers-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(root, rel);
      mkdirSync(join(abs, '..'), { recursive: true });
      writeFileSync(abs, content);
    }
    return await headersProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'src')], log: () => {} }),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('express app with no security headers → advisory', async () => {
  const findings = await scan({
    'package.json': JSON.stringify({ dependencies: { express: '^4.18.0' } }),
    'src/app.js': "const app = require('express')();\napp.get('/', (req, res) => res.send('hi'));\n",
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'no-security-headers');
  assert.equal(findings[0].advisory, true);
  assert.equal(findings[0].pillar, 'security');
});

test('express app using helmet → silent', async () => {
  const findings = await scan({
    'package.json': JSON.stringify({ dependencies: { express: '^4.18.0', helmet: '^7.0.0' } }),
    'src/app.js': "const helmet = require('helmet');\nconst app = require('express')();\napp.use(helmet());\n",
  });
  assert.equal(findings.length, 0);
});

test('static (non-server) app → skipped, no finding', async () => {
  const findings = await scan({
    'package.json': JSON.stringify({ dependencies: { react: '^18' } }),
    'src/app.jsx': 'export default () => <div/>;\n',
  });
  assert.equal(findings.length, 0);
});

test('flask app with Talisman → silent', async () => {
  const findings = await scan({
    'requirements.txt': 'flask==2.3.0\nflask-talisman==1.0\n',
    'src/app.py': 'from flask import Flask\nfrom flask_talisman import Talisman\napp = Flask(__name__)\nTalisman(app)\n',
  });
  assert.equal(findings.length, 0);
});

test('flask app with no header config → advisory', async () => {
  const findings = await scan({
    'requirements.txt': 'flask==2.3.0\n',
    'src/app.py': 'from flask import Flask\napp = Flask(__name__)\n',
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source.ruleId, 'no-security-headers');
  assert.equal(findings[0].advisory, true);
});
