// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the rate-limiting advisory provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rateLimitProvider } from '../src/providers/ratelimit.mjs';

/** Run the provider against a temp repo whose content is built by `setup`.
 * @param {(root: string) => void} setup
 * @returns {Promise<import('../src/types.mjs').Finding[]>}
 */
async function runFixture(setup) {
  const root = mkdtempSync(join(tmpdir(), 'vibe-check-ratelimit-'));
  try {
    await setup(root);
    return await rateLimitProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [root], log: () => {} }),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('flags an Express app with no rate-limiting evidence as advisory', async () => {
  const findings = await runFixture((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { express: '^5' } }));
    writeFileSync(join(root, 'src', 'app.ts'), "import express from 'express';\nexport const app = express();\n");
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.source.ruleId, 'no-rate-limiting');
  assert.equal(findings[0]?.advisory, true);
  assert.equal(findings[0]?.severity, 'medium');
  assert.equal(findings[0]?.pillar, 'security');
  assert.equal(findings[0]?.teardownId, null);
});

test('stays silent when an express-rate-limit dependency exists', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(
      join(root, 'package.json'),
      JSON.stringify({ dependencies: { express: '^5', 'express-rate-limit': '^7' } }),
    );
  });
  assert.equal(findings.length, 0);
});

test('stays silent on recognizable limiter usage in code', async () => {
  const findings = await runFixture((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { fastify: '^5' } }));
    writeFileSync(
      join(root, 'src', 'app.ts'),
      "import { rateLimit } from '@fastify/rate-limit';\napp.register(rateLimit, { max: 100 });\n",
    );
  });
  assert.equal(findings.length, 0);
});

test('stays silent on Python limiter usage (slowapi)', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(join(root, 'requirements.txt'), 'flask==3.0\nslowapi==0.1.9\n');
  });
  assert.equal(findings.length, 0);
});

test('flags a Flask app with no limiter as advisory', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(join(root, 'requirements.txt'), 'flask==3.0\n');
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.source.ruleId, 'no-rate-limiting');
});

test('stays silent on committed nginx limit_req config', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { express: '^5' } }));
    writeFileSync(
      join(root, 'nginx.conf'),
      'limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\nserver { limit_req zone=api burst=20; }\n',
    );
  });
  assert.equal(findings.length, 0);
});

test('is silent for non-server repos', async () => {
  const findings = await runFixture((root) => {
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { react: '^19' } }));
  });
  assert.equal(findings.length, 0);
});
