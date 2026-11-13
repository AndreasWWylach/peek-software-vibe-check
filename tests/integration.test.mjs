// @ts-check
/**
 * @fileoverview End-to-end integration tests — run the full engine against a
 * small sample app and assert the report.
 *
 * Requires the `semgrep` and `madge` binaries (each test skips when its binary
 * is missing). The OSV provider is left unasserted: it depends on osv-scanner +
 * the network, so these tests focus on the deterministic Semgrep + Madge paths
 * while still exercising the whole pipeline (config load → providers → dedup →
 * score → render → schema self-check).
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
const madgeAvailable = commandAvailable('madge');
const sccAvailable = commandAvailable('scc');

/** Absolute path to the checked-in monolithic-file fixture. */
const MONOLITH_FIXTURE = fileURLToPath(new URL('../examples/monolith-fixture', import.meta.url));

/**
 * Run the engine once against the sample app.
 * @returns {Promise<{ report: Report; outDir: string }>}
 */
async function runOnce() {
  const outDir = await mkdtemp(join(tmpdir(), 'vibe-check-'));
  const report = /** @type {Report} */ (
    await run(join(SAMPLE_APP, 'peek-config.json'), {
      repoRoot: SAMPLE_APP,
      outDir,
      quiet: true,
    })
  );
  return { report, outDir };
}

test(
  'semgrep provider: reports TD-016 + TD-045 and writes artifacts',
  { skip: semgrepAvailable ? false : 'semgrep not installed — integration test skipped' },
  async () => {
    const { report, outDir } = await runOnce();

    const teardowns = report.findings.filter((finding) => finding.kind === 'teardown').map((finding) => finding.teardownId);
    assert.ok(report.riskScore.total > 0, 'expected a non-zero risk score');
    assert.ok(teardowns.includes('TD-016'), 'expected TD-016 to fire');
    assert.ok(teardowns.includes('TD-045'), 'expected TD-045 to fire');

    // Calibration overlay: the config carries quiz data, and Q1.1 maps to
    // TD-016, which the scan found.
    const calibration = report.calibration;
    assert.ok(calibration, 'expected calibration when quiz data is present');
    if (!calibration) throw new Error('missing calibration');
    assert.equal(calibration.selfReport, 142);
    const moment = calibration.moments.find((m) => m.questionId === 'Q1.1');
    assert.equal(moment?.teardownId, 'TD-016');
    assert.equal(moment?.found, true);

    // Both artifacts were written, and the JSON self-check already passed.
    const json = JSON.parse(await readFile(join(outDir, 'peek-report.json'), 'utf8'));
    assert.equal(json.riskScore.total, report.riskScore.total);
    const markdown = await readFile(join(outDir, 'AUDIT-REPORT.md'), 'utf8');
    assert.ok(markdown.includes('TD-016'), 'expected the Markdown report to mention TD-016');
  },
);

test(
  'madge provider: reports TD-021 circular dependency',
  { skip: madgeAvailable ? false : 'madge not installed — integration test skipped' },
  async () => {
    const { report } = await runOnce();
    const circular = report.findings.filter((finding) => finding.teardownId === 'TD-021');
    assert.ok(circular.length > 0, 'expected a TD-021 circular-dependency finding');
  },
);

test(
  'scc provider: reports TD-019 monolithic file (over ruleParams threshold)',
  { skip: sccAvailable ? false : 'scc not installed — integration test skipped' },
  async () => {
    const outDir = await mkdtemp(join(tmpdir(), 'vibe-check-'));
    const report = /** @type {Report} */ (
      await run(join(MONOLITH_FIXTURE, 'peek-config.json'), {
        repoRoot: MONOLITH_FIXTURE,
        outDir,
        quiet: true,
      })
    );
    const monolithic = report.findings.filter((finding) => finding.teardownId === 'TD-019');
    assert.equal(monolithic.length, 1, 'expected exactly one TD-019 finding');
    assert.equal(monolithic[0]?.file, 'src/big.ts');
    assert.equal(monolithic[0]?.pillar, 'architecture');
    assert.equal(monolithic[0]?.severity, 'high');
  },
);
