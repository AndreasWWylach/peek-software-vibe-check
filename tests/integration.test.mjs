// @ts-check
/**
 * @fileoverview End-to-end integration test — run the full engine against a
 * small sample app and assert the report.
 *
 * Requires the `semgrep` binary (skipped otherwise). The OSV provider is left
 * unasserted: it depends on osv-scanner + the network, so this test focuses on
 * the deterministic Semgrep path while still exercising the whole pipeline
 * (config load → providers → dedup → score → render → schema self-check).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from '../src/run.mjs';
import { commandAvailable } from '../src/proc.mjs';

/** @typedef {import('../src/types.mjs').Report} Report */

/** Absolute path to the checked-in sample app fixture. */
const SAMPLE_APP = fileURLToPath(new URL('../examples/sample-app', import.meta.url));

const semgrepAvailable = commandAvailable('semgrep');

test(
  'engine runs end-to-end and reports TD-016 + TD-045 findings',
  { skip: semgrepAvailable ? false : 'semgrep not installed — integration test skipped' },
  async () => {
    const outDir = await mkdtemp(join(tmpdir(), 'vibe-check-'));
    const report = /** @type {Report} */ (
      await run(join(SAMPLE_APP, 'peek-config.json'), {
        repoRoot: SAMPLE_APP,
        outDir,
        quiet: true,
      })
    );

    const teardowns = report.findings.filter((finding) => finding.kind === 'teardown').map((finding) => finding.teardownId);
    assert.ok(report.riskScore.total > 0, 'expected a non-zero risk score');
    assert.ok(teardowns.includes('TD-016'), 'expected TD-016 to fire');
    assert.ok(teardowns.includes('TD-045'), 'expected TD-045 to fire');

    // Both artifacts were written, and the JSON self-check already passed.
    const json = JSON.parse(await readFile(join(outDir, 'peek-report.json'), 'utf8'));
    assert.equal(json.riskScore.total, report.riskScore.total);
    const markdown = await readFile(join(outDir, 'AUDIT-REPORT.md'), 'utf8');
    assert.ok(markdown.includes('TD-016'), 'expected the Markdown report to mention TD-016');
  },
);
