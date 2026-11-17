// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for provider JSON parsers (semgrep + osv-scanner).
 *
 * The providers shell out to external binaries; these tests pin how their
 * `--json` output maps into the shared finding shape — deterministically, with
 * canned outputs, so the mapping is verified without the binaries or a network.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseSemgrepJson } from '../src/providers/semgrep.mjs';
import { collectRootLockfiles, parseOsvJson } from '../src/providers/osv.mjs';
import { isSecretConfigFile } from '../src/ignore.mjs';
import { isInertSecret, isPublicByDesignValue } from '../src/secretClassify.mjs';
import { parseMadgeJson } from '../src/providers/madge.mjs';
import { parseSccJson } from '../src/providers/scc.mjs';
import { parseGitleaksJson } from '../src/providers/gitleaks.mjs';
import { parseEslintJson } from '../src/providers/eslint.mjs';

test('semgrep: maps a result with metadata.peek into a teardown finding', () => {
  const output = JSON.stringify({
    results: [
      {
        check_id: 'rules.peek.TD-008.peek-td-008-idor-unscoped-lookup-typescript',
        path: '/repo/src/routes/projects.ts',
        start: { line: 11, col: 32 },
        end: { line: 11, col: 50 },
        extra: {
          message: 'Prisma query scoped by a raw id only',
          severity: 'ERROR',
          metadata: {
            peek: {
              teardownId: 'TD-008',
              pillar: 'security',
              severity: 'critical',
              title: 'Lookup by raw id without tenant scope',
              fixSummary: 'Scope every query to the authenticated tenant.',
            },
          },
        },
      },
    ],
  });

  const [finding] = parseSemgrepJson(output, '/repo');
  assert.equal(finding.kind, 'teardown');
  assert.equal(finding.teardownId, 'TD-008');
  assert.equal(finding.pillar, 'security');
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.file, 'src/routes/projects.ts');
  assert.equal(finding.line, 11);
  assert.equal(finding.column, 32);
  assert.equal(finding.title, 'Lookup by raw id without tenant scope');
  assert.equal(finding.fixSummary, 'Scope every query to the authenticated tenant.');
  assert.equal(finding.source.provider, 'semgrep');
});

test('semgrep: falls back to semgrep severity + qa pillar when peek metadata is thin', () => {
  const output = JSON.stringify({
    results: [
      {
        check_id: 'rules.peek.TD-045.peek-td-045-ts-escape-hatch-typescript',
        path: '/repo/src/a.ts',
        start: { line: 2, col: 3 },
        end: { line: 2, col: 16 },
        extra: { message: 'ts-ignore', severity: 'WARNING', metadata: { peek: { teardownId: 'TD-045' } } },
      },
    ],
  });

  const [finding] = parseSemgrepJson(output, '/repo');
  assert.equal(finding.teardownId, 'TD-045');
  assert.equal(finding.severity, 'medium'); // WARNING → medium
  assert.equal(finding.pillar, 'qa'); // default when peek.pillar is missing
});

test('osv: maps v2 groups (max_severity CVSS) into a dependency finding', () => {
  const output = JSON.stringify({
    results: [
      {
        source: { path: '/repo/package-lock.json', type: 'lockfile' },
        packages: [
          {
            package: { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
            groups: [
              { ids: ['GHSA-35jh-r3h4-6jhm'], aliases: ['CVE-2021-23337'], max_severity: '8.1' },
            ],
          },
        ],
      },
    ],
  });

  const [finding] = parseOsvJson(output, '/repo');
  assert.equal(finding.kind, 'dependency');
  assert.equal(finding.pillar, 'security');
  assert.equal(finding.severity, 'high'); // 8.1 → high
  assert.equal(finding.file, 'package-lock.json');
  assert.equal(finding.dependency?.package, 'lodash');
  assert.equal(finding.dependency?.version, '4.17.20');
  assert.deepEqual(finding.dependency?.cveIds, ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm']);
});

test('osv: buckets a 9.x CVSS score as critical', () => {
  const output = JSON.stringify({
    results: [
      {
        source: { path: '/repo/package-lock.json', type: 'lockfile' },
        packages: [
          {
            package: { name: 'x', version: '1.0.0', ecosystem: 'npm' },
            groups: [{ ids: ['GHSA-1'], aliases: ['CVE-2026-0001'], max_severity: '9.8' }],
          },
        ],
      },
    ],
  });

  const [finding] = parseOsvJson(output, '/repo');
  assert.equal(finding.severity, 'critical');
});

test('osv: falls back to database_specific.severity when groups are absent', () => {
  const output = JSON.stringify({
    results: [
      {
        source: { path: '/repo/requirements.txt', type: 'lockfile' },
        packages: [
          {
            package: { name: 'requests', version: '2.25.0', ecosystem: 'PyPI' },
            vulnerabilities: [
              { id: 'CVE-2021-0000', summary: 'x', aliases: [], database_specific: { severity: 'MODERATE' } },
            ],
          },
        ],
      },
    ],
  });

  const [finding] = parseOsvJson(output, '/repo');
  assert.equal(finding.severity, 'medium');
  assert.deepEqual(finding.dependency?.cveIds, ['CVE-2021-0000']);
});

test('osv: defaults severity to medium when the scanner reports none', () => {
  const output = JSON.stringify({
    results: [
      {
        source: { path: '/repo/requirements.txt', type: 'lockfile' },
        packages: [
          {
            package: { name: 'requests', version: '2.25.0', ecosystem: 'PyPI' },
            vulnerabilities: [{ id: 'CVE-2021-0000', summary: 'unknown severity', aliases: [] }],
          },
        ],
      },
    ],
  });

  const [finding] = parseOsvJson(output, '/repo');
  assert.equal(finding.severity, 'medium');
  assert.deepEqual(finding.dependency?.cveIds, ['CVE-2021-0000']);
});

test('collectRootLockfiles finds root lockfiles only (not arbitrary files)', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-osv-'));
  try {
    writeFileSync(join(root, 'composer.lock'), '{}');
    writeFileSync(join(root, 'package-lock.json'), '{}');
    writeFileSync(join(root, 'README.md'), 'not a lockfile');
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src', 'app.php'), '<?php');

    const found = collectRootLockfiles(root).map((file) => file.split('/').pop()).sort();
    assert.deepEqual(found, ['composer.lock', 'package-lock.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('isSecretConfigFile flags conventional secret config locations', () => {
  assert.equal(isSecretConfigFile('config/parameters.yaml'), true);
  assert.equal(isSecretConfigFile('environments/dev/config/database.yaml'), true);
  assert.equal(isSecretConfigFile('database.yaml'), true); // root-level convention
  assert.equal(isSecretConfigFile('.github/workflows/ci.yml'), true); // yaml
  assert.equal(isSecretConfigFile('src/Service/App.php'), false); // PHP is code, not config
  assert.equal(isSecretConfigFile('src/keys.ts'), false); // client code
  assert.equal(isSecretConfigFile('public/js/app.js'), false); // client code
});

test('madge: parses circular cycles into path arrays', () => {
  const output = JSON.stringify([
    ['src/a.ts', 'src/b.ts'],
    ['src/c.ts', 'src/d.ts', 'src/e.ts'],
  ]);
  assert.deepEqual(parseMadgeJson(output), [
    ['src/a.ts', 'src/b.ts'],
    ['src/c.ts', 'src/d.ts', 'src/e.ts'],
  ]);
});

test('madge: ignores empty and self-referential cycles', () => {
  const output = JSON.stringify([['only.ts'], []]);
  assert.deepEqual(parseMadgeJson(output), []);
});

test('scc: flattens per-language groups into per-file line counts', () => {
  const output = JSON.stringify([
    {
      Name: 'TypeScript',
      Files: [
        { Location: 'src/big.ts', Lines: 600, Code: 510 },
        { Location: 'src/small.ts', Lines: 3, Code: 1 },
      ],
    },
    { Name: 'Python', Files: [{ Location: 'app/main.py', Lines: 42, Code: 30 }] },
  ]);
  assert.deepEqual(parseSccJson(output), [
    { location: 'src/big.ts', lines: 600, code: 510 },
    { location: 'src/small.ts', lines: 3, code: 1 },
    { location: 'app/main.py', lines: 42, code: 30 },
  ]);
});

test('scc: tolerates empty output and missing file lists', () => {
  assert.deepEqual(parseSccJson('[]'), []);
  assert.deepEqual(parseSccJson(JSON.stringify([{ Name: 'Go' }])), []);
});

test('gitleaks: maps leaks to finding fields and drops the secret value', () => {
  const output = JSON.stringify([
    {
      RuleID: 'generic-api-key',
      Description: 'Generic API Key',
      StartLine: 4,
      File: '/repo/src/keys.ts',
      Secret: 'supersecretvalue',
      Match: 'apiKey = "supersecretvalue"',
    },
  ]);
  const [leak] = parseGitleaksJson(output);
  assert.equal(leak.ruleId, 'generic-api-key');
  assert.equal(leak.description, 'Generic API Key');
  assert.equal(leak.file, '/repo/src/keys.ts');
  assert.equal(leak.line, 4);
  assert.ok(!('secret' in leak) && !('match' in leak), 'parsed leaks must not carry the secret or match text');
});

test('gitleaks: tolerates empty output', () => {
  assert.deepEqual(parseGitleaksJson('[]'), []);
});

test('gitleaks: isPublicByDesignValue skips Firebase Auth REST keys and App Check site keys', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vibe-check-gitleaks-'));
  try {
    // A driver of the Firebase Auth REST API carries the public web apiKey.
    const pilot = join(dir, 'pilot.mjs');
    writeFileSync(pilot, "fetch('https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=' + K);");
    const aiKeyLine = "const K = 'AIzaSyQFwAfGoCsheReohWSvhShgW7mOhIlMQGa';";
    assert.equal(isPublicByDesignValue(aiKeyLine, pilot), true, 'AIzaSy key in a Firebase Auth REST driver is public by design');

    // The same AIzaSy value WITHOUT Identity Toolkit usage is a real leak.
    const server = join(dir, 'server.ts');
    writeFileSync(server, '');
    assert.equal(isPublicByDesignValue(aiKeyLine, server), false, 'AIzaSy key without Identity Toolkit usage stays flagged');

    // App Check / reCAPTCHA site key, labelled as such in source.
    const config = join(dir, 'config.ts');
    writeFileSync(config, '');
    const siteKeyLine = "export const DEFAULT_APP_CHECK_SITE_KEY = '6LcABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a';";
    assert.equal(isPublicByDesignValue(siteKeyLine, config), true, 'labelled App Check site key is public by design');

    // The same 6L… value NOT labelled as a site key stays flagged (secret key).
    assert.equal(isPublicByDesignValue("export const recaptcha = '6LcABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a';", config), false, 'unlabelled 6L… value stays flagged');

    // An ordinary API key is never public by design.
    assert.equal(isPublicByDesignValue("export const apiKey = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';", config), false, 'ordinary API key is not public by design');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('gitleaks: isInertSecret skips placeholders and alphabet constants', () => {
  // Placeholder secret values (the underscore before `placeholder` must not
  // defeat the match).
  assert.equal(isInertSecret('STRIPE_SECRET_KEY=sk_test_placeholder'), true);
  assert.equal(isInertSecret('STRIPE_WEBHOOK_SECRET=whsec_placeholder2'), true);
  assert.equal(isInertSecret('EMAIL_API_KEY=placeholder'), true);
  assert.equal(isInertSecret('const key = "changeme";'), true);

  // Alphabet / character-set constants.
  assert.equal(isInertSecret("const TOKEN_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';"), true);
  assert.equal(isInertSecret("const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';"), true);

  // Real secrets are NOT inert.
  assert.equal(isInertSecret("const apiKey = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';"), false, 'ordinary API key is not inert');
  assert.equal(isInertSecret("const stripe = 'sk_test_51Hq7abcdefghijklmnop';"), false, 'real Stripe test key is not inert');
});

test('eslint: maps messages to hygiene findings (error→medium, warn→low)', () => {
  const output = JSON.stringify([
    {
      filePath: '/repo/src/app.js',
      messages: [
        { ruleId: 'no-unreachable', severity: 2, message: 'Unreachable code.', line: 4, column: 3 },
        { ruleId: 'no-unused-vars', severity: 1, message: "'unused' is never used.", line: 2, column: 9 },
      ],
    },
  ]);
  assert.deepEqual(parseEslintJson(output), [
    { file: '/repo/src/app.js', ruleId: 'no-unreachable', severity: 'medium', line: 4, column: 3, message: 'Unreachable code.' },
    { file: '/repo/src/app.js', ruleId: 'no-unused-vars', severity: 'low', line: 2, column: 9, message: "'unused' is never used." },
  ]);
});

test('eslint: ignores fatal messages (no ruleId) and tolerates non-JSON', () => {
  const output = JSON.stringify([{ filePath: '/repo/src/x.ts', messages: [{ fatal: true, severity: 2, message: 'Parsing error' }] }]);
  assert.deepEqual(parseEslintJson(output), []);
  assert.deepEqual(parseEslintJson(''), []);
  assert.deepEqual(parseEslintJson('not json'), []);
});
