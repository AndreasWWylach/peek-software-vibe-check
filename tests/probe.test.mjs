// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for the live deployment probe — the deterministic, offline
 * pieces (target validation, SPA-fallback heuristic, asset extraction). The
 * network layer is a thin fetch wrapper, exercised by real probes, not tests.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractSameOriginAssets, looksLikeSpaFallback, validateProbeUrl } from '../src/probe.mjs';

test('validateProbeUrl accepts a public https URL', () => {
  const result = validateProbeUrl('https://app.example.com');
  assert.equal(result.ok, true);
  assert.equal(/** @type {{ url: URL }} */ (result).url.hostname, 'app.example.com');
});

test('validateProbeUrl accepts http (the probe warns on missing HTTPS later)', () => {
  const result = validateProbeUrl('http://app.example.com');
  assert.equal(result.ok, true);
});

test('validateProbeUrl rejects malformed and non-http(s) input', () => {
  assert.equal(validateProbeUrl('not a url').ok, false);
  assert.equal(validateProbeUrl('ftp://example.com').ok, false);
  assert.equal(validateProbeUrl('file:///etc/passwd').ok, false);
});

test('validateProbeUrl rejects loopback and private-network hosts', () => {
  for (const host of [
    'localhost',
    'sub.localhost',
    'app.local',
    '127.0.0.1',
    '127.8.8.8',
    '10.0.0.5',
    '192.168.1.10',
    '169.254.169.254', // cloud metadata address
    '172.16.0.1',
    '172.31.255.255',
    '[::1]',
  ]) {
    const result = validateProbeUrl(`https://${host}`);
    assert.equal(result.ok, false, `${host} must be rejected`);
    assert.match(/** @type {{ reason: string }} */ (result).reason, /loopback|private/i);
  }
});

test('looksLikeSpaFallback ignores 200 HTML responses (SPA rewrite)', () => {
  const html = new Headers({ 'content-type': 'text/html; charset=utf-8' });
  assert.equal(looksLikeSpaFallback({ status: 200, headers: html, body: '<html>' }), true);
  const plain = new Headers({ 'content-type': 'text/plain' });
  assert.equal(looksLikeSpaFallback({ status: 200, headers: plain, body: 'ref: refs/heads/main' }), false);
  const missing = new Headers();
  assert.equal(looksLikeSpaFallback({ status: 404, headers: missing, body: '' }), false);
});

test('extractSameOriginAssets finds local script srcs and skips the rest', () => {
  const base = new URL('https://app.example.com/');
  const html = `
    <script src="/assets/index-abc.js"></script>
    <script src="https://app.example.com/chunk-1.js"></script>
    <script src="https://cdn.example.net/lib.js"></script>
    <script src="/assets/index-abc.js"></script>
    <script src="/styles.css"></script>
    <link rel="modulepreload" href="/assets/index-abc.js">
  `;
  const assets = extractSameOriginAssets(base, html);
  assert.deepEqual(
    assets.map((url) => url.pathname).sort(),
    ['/assets/index-abc.js', '/chunk-1.js'],
  );
});

test('extractSameOriginAssets tolerates malformed src attributes', () => {
  const base = new URL('https://app.example.com/');
  const assets = extractSameOriginAssets(base, '<script src="not a url"></script><script src="/ok.js"></script>');
  assert.deepEqual(assets.map((url) => url.pathname), ['/ok.js']);
});
