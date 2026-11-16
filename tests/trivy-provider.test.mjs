// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the Trivy provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { trivyProvider, parseTrivyJson } from '../src/providers/trivy.mjs';

test('parseTrivyJson maps vulnerabilities to dependency findings + secrets to advisory', () => {
  const stdout = JSON.stringify({
    Results: [
      {
        Target: 'backend/package-lock.json',
        Class: 'lang-pkgs',
        Type: 'npm',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2026-40181',
            PkgName: '@remix-run/router',
            InstalledVersion: '1.23.2',
            FixedVersion: '1.23.3',
            Severity: 'MEDIUM',
            Title: 'Prototype pollution in @remix-run/router',
            Description: 'Some description',
          },
        ],
      },
      {
        Target: 'frontend/src/config.js',
        Class: 'secret',
        Secrets: [
          {
            RuleID: 'stripe-secret-token',
            Category: 'Stripe',
            Severity: 'CRITICAL',
            Title: 'Stripe Secret Key',
            StartLine: 11,
            EndLine: 11,
            Code: 'sk_test_xxx',
            Match: 'sk_test_xxx',
          },
        ],
      },
    ],
  });

  const findings = parseTrivyJson(stdout, '/repo');
  assert.equal(findings.length, 2);

  const vuln = findings.find((f) => f.kind === 'dependency');
  assert.ok(vuln);
  assert.equal(vuln.source.provider, 'trivy');
  assert.equal(vuln.dependency?.package, '@remix-run/router');
  assert.equal(vuln.dependency?.version, '1.23.2');
  assert.equal(vuln.dependency?.ecosystem, 'npm');
  assert.deepEqual(vuln.dependency?.cveIds, ['CVE-2026-40181']);
  assert.equal(vuln.severity, 'medium');

  const secret = findings.find((f) => f.kind === 'hygiene');
  assert.ok(secret);
  assert.equal(secret.advisory, true);
  assert.equal(secret.pillar, 'security');
  assert.equal(secret.severity, 'critical');
  assert.equal(secret.file, 'frontend/src/config.js');
  assert.equal(secret.line, 11);
  assert.equal(secret.source.ruleId, 'stripe-secret-token');
  // The secret VALUE must never be echoed.
  assert.ok(!JSON.stringify(secret).includes('sk_test_xxx'), 'secret value must not leak');
});

test('trivy provider skips gracefully when the repo has no manifests', async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-trivy-'));
  try {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src', 'app.js'), 'export const x = 1;\n');
    const findings = await trivyProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'src')], log: () => {} }),
    );
    assert.deepEqual(findings, []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
