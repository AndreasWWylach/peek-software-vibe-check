// @ts-check
/**
 * @fileoverview Orchestrator — wires config → providers → dedup → score → report.
 *
 * This is the single entry point used by the CLI. It is deterministic in its
 * findings and score (stable ordering, capped totals); only `generatedAt`
 * varies with the wall clock.
 */
import { resolve } from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.mjs';
import { runProviders } from './providers/registry.mjs';
import { semgrepProvider } from './providers/semgrep.mjs';
import { osvProvider } from './providers/osv.mjs';
import { madgeProvider } from './providers/madge.mjs';
import { dedupeFindings, sortFindings } from './findings.mjs';
import { computeScores, MAX_TOTAL_SCORE } from './scoring.mjs';
import { computeCalibration } from './calibration.mjs';
import { listTeardowns } from './catalog.mjs';
import { renderMarkdown } from './report.mjs';
import { createValidator, loadSchema, validate } from './schema-loader.mjs';
import { ENGINE_NAME, ENGINE_VERSION, readCommit } from './version.mjs';

/** @typedef {import('./types.mjs').Report} Report */
/** @typedef {import('./types.mjs').RunContext} RunContext */

/** Absolute path to the published report schema (used for the output self-check). */
const REPORT_SCHEMA_PATH = fileURLToPath(new URL('../schema/peek-report.schema.json', import.meta.url));

/**
 * Run the full audit: load config, run providers, dedupe, score, render, write.
 * @param {string} configPath — absolute path to `peek-config.json`.
 * @param {{ repoRoot: string; outDir: string; quiet: boolean }} options
 * @returns {Promise<Report>} the generated report (also written to disk).
 */
export async function run(configPath, options) {
  const config = await loadConfig(configPath);
  const log = options.quiet
    ? /** @type {(line: string) => void} */ (() => {})
    : /** @param {string} line */ (line) => console.log(line);

  log(`${ENGINE_NAME} ${ENGINE_VERSION} — local deep scan`);
  log(`config: ${configPath}`);

  const targets = config.targets.map((target) => resolve(options.repoRoot, target));

  /** @type {RunContext} */
  const ctx = { repoRoot: options.repoRoot, targets, log };

  const { findings, skipped } = await runProviders([semgrepProvider, osvProvider, madgeProvider], config, ctx);
  const sorted = sortFindings(dedupeFindings(findings));
  const scores = computeScores(sorted);

  const { total, max, tier, riskPercentage } = scores;
  const teardownFacts = await listTeardowns();
  const calibration = computeCalibration({
    quiz: config.quiz,
    scanTotal: total,
    scanPillars: scores.pillars,
    findings: sorted,
    teardownFacts,
  });

  const report = /** @type {Report} */ ({
    schemaVersion: 1,
    engine: { name: ENGINE_NAME, version: ENGINE_VERSION, commit: readCommit() },
    generatedAt: new Date().toISOString(),
    riskScore: { total, max, tier, riskPercentage },
    pillars: scores.pillars,
    findings: sorted,
    skippedProviders: skipped,
    notStaticallyVerifiable: [],
    ...(calibration ? { calibration } : {}),
  });

  // Self-check: the engine's own output must satisfy the published contract.
  const reportErrors = validate(createValidator(), await loadSchema(REPORT_SCHEMA_PATH), report);
  if (reportErrors.length > 0) {
    throw new Error(`Internal error: generated report failed schema validation:\n  - ${reportErrors.join('\n  - ')}`);
  }

  await mkdir(options.outDir, { recursive: true });
  await writeFile(resolve(options.outDir, 'peek-report.json'), JSON.stringify(report, null, 2) + '\n', 'utf8');
  await writeFile(resolve(options.outDir, 'AUDIT-REPORT.md'), renderMarkdown(report), 'utf8');

  log(`risk score: ${total} / ${MAX_TOTAL_SCORE} (${tier})`);
  log(`wrote peek-report.json + AUDIT-REPORT.md`);

  return report;
}
