// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for cross-tool corroboration (gitleaks ↔ trivy
 * secrets; osv-scanner ↔ trivy dependency CVEs).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { corroborateFindings, dedupeFindings } from '../src/findings.mjs';

/** @type {(p: string, r: string, f: string, l: number, kind?: 'teardown'|'hygiene'|'dependency') => import('../src/types.mjs').Finding} */
function make(provider, ruleId, file, line, kind = 'hygiene') {
  return {
    id: `${provider}:${ruleId}:${file}:${line}`,
    kind,
    file,
    line,
    column: null,
    severity: kind === 'teardown' ? 'critical' : 'medium',
    pillar: 'security',
    teardownId: kind === 'teardown' ? 'TD-016' : null,
    title: `${provider} secret at ${file}:${line}`,
    message: null,
    fixSummary: null,
    source: { provider, ruleId },
    dependency: null,
    advisory: kind === 'hygiene',
  };
}

test('corroborateFindings collapses gitleaks + trivy secret overlap, recording corroboration', () => {
  const gitleaks = make('gitleaks', 'generic-api-key', 'src/config.js', 11, 'teardown');
  const trivy = make('trivy', 'stripe-secret-token', 'src/config.js', 11, 'hygiene');

  const result = corroborateFindings([gitleaks, trivy]);
  assert.equal(result.length, 1);
  assert.equal(result[0].source.provider, 'gitleaks');
  assert.deepEqual(result[0].corroboratedBy, ['trivy']);
  // Highest severity wins (gitleaks teardown is critical).
  assert.equal(result[0].severity, 'critical');
});

test('corroborateFindings keeps different-line secrets separate', () => {
  const a = make('gitleaks', 'generic-api-key', 'src/config.js', 11, 'teardown');
  const b = make('trivy', 'stripe-secret-token', 'src/config.js', 22, 'hygiene');
  assert.equal(corroborateFindings([a, b]).length, 2);
});

test('dedupeFindings merges osv + trivy dependency findings, unioning CVE ids + corroboration', () => {
  /** @type {import('../src/types.mjs').Finding} */
  const osv = {
    id: 'osv:vite',
    kind: 'dependency',
    file: 'package-lock.json',
    line: null,
    column: null,
    severity: 'high',
    pillar: 'security',
    teardownId: null,
    title: 'vite',
    message: null,
    fixSummary: null,
    source: { provider: 'osv', ruleId: 'osv' },
    dependency: { package: 'vite', version: '8.0.14', ecosystem: 'npm', cveIds: ['CVE-2026-112942'] },
  };
  /** @type {import('../src/types.mjs').Finding} */
  const trivy = {
    id: 'trivy:vite',
    kind: 'dependency',
    file: 'package-lock.json',
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'security',
    teardownId: null,
    title: 'vite',
    message: null,
    fixSummary: null,
    source: { provider: 'trivy', ruleId: 'CVE-2026-112943' },
    dependency: { package: 'vite', version: '8.0.14', ecosystem: 'npm', cveIds: ['CVE-2026-112943'] },
  };

  const merged = dedupeFindings([osv, trivy]);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].dependency?.cveIds, ['CVE-2026-112942', 'CVE-2026-112943']);
  assert.deepEqual(merged[0].corroboratedBy, ['trivy']);
});
