// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

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
import { sccProvider } from './providers/scc.mjs';
import { gitleaksProvider } from './providers/gitleaks.mjs';
import { eslintProvider } from './providers/eslint.mjs';
import { testsProvider } from './providers/tests.mjs';
import { firebaseProvider } from './providers/firebase.mjs';
import { depsProvider } from './providers/deps.mjs';
import { headersProvider } from './providers/headers.mjs';
import { ciProvider } from './providers/ci.mjs';
import { checkovProvider } from './providers/checkov.mjs';
import { hadolintProvider } from './providers/hadolint.mjs';
import { trivyProvider } from './providers/trivy.mjs';
import { banditProvider } from './providers/bandit.mjs';
import { gosecProvider } from './providers/gosec.mjs';
import { phpstanProvider } from './providers/phpstan.mjs';
import { isTestFile } from './ignore.mjs';
import { discoverSourceDirs } from './discover.mjs';
import { detectAppCheckOff, detectStack } from './stack.mjs';
import { corroborateFindings, dedupeFindings, sortFindings } from './findings.mjs';
import { computeScores, MAX_TOTAL_SCORE, summarizeDependencies } from './scoring.mjs';
import { computeCalibration } from './calibration.mjs';
import { computeReadiness } from './readiness.mjs';
import { listTeardowns } from './catalog.mjs';
import { renderMarkdown } from './report.mjs';
import { createValidator, loadSchema, validate } from './schema-loader.mjs';
import { ENGINE_NAME, ENGINE_VERSION, readCommit } from './version.mjs';

/** @typedef {import('./types.mjs').Report} Report */
/** @typedef {import('./types.mjs').RunContext} RunContext */
/** @typedef {import('./types.mjs').DisabledCheck} DisabledCheck */

/** Absolute path to the published report schema (used for the output self-check). */
const REPORT_SCHEMA_PATH = fileURLToPath(new URL('../schema/peek-report.schema.json', import.meta.url));

/**
 * True when a `ci`-provider advisory with the given ruleId is present.
 * @param {import('./types.mjs').Finding[]} findings
 * @param {string} ruleId
 * @returns {boolean}
 */
function hasCiAdvisory(findings, ruleId) {
  return findings.some((f) => f.source.provider === 'ci' && f.source.ruleId === ruleId);
}

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

  // `targets` are a hint from the manifest intake — but the upload may miss
  // whole folders (e.g. `shared/`). The engine runs on the full repo, so it
  // auto-includes any top-level directory containing source code of the
  // configured languages. No silently unchecked code. The config may `exclude`
  // repo-relative path prefixes (fixtures, vendored code) from both explicit
  // targets and auto-included dirs.
  const excludes = (config.exclude ?? []).map(normalizeRelPath);
  const configured = new Set(config.targets.map((target) => target.replace(/[/\\]+$/, '')));
  const autoIncluded = discoverSourceDirs(options.repoRoot, config.languages)
    .filter((dir) => !configured.has(dir.replace(/\/$/, '')))
    .filter((dir) => !isExcludedPath(excludes, dir));
  const explicitTargets = config.targets.filter((target) => !isExcludedPath(excludes, target));
  const excludedConfigured = config.targets.filter((target) => isExcludedPath(excludes, target));
  if (excludedConfigured.length > 0) {
    log(`  excluded configured target(s): ${excludedConfigured.join(', ')}`);
  }
  if (autoIncluded.length > 0) {
    log(`  auto-included source dir(s) not in config: ${autoIncluded.join(', ')}`);
  }
  const targets = [
    ...explicitTargets.map((target) => resolve(options.repoRoot, target)),
    ...autoIncluded.map((dir) => resolve(options.repoRoot, dir)),
  ];

  // Detect the app stack ONCE — both the report's App Stack summary and the
  // framework-gated providers (Semgrep PHP packs, phpstan) read the same
  // markers, so they never disagree about what the app is built on.
  const stack = detectStack(options.repoRoot, targets);

  /** @type {DisabledCheck[]} */
  const disabled = [];
  /** @type {RunContext} */
  const ctx = {
    repoRoot: options.repoRoot,
    targets,
    stack,
    log,
    noteDisabled: (id, detail) => disabled.push({ id, detail }),
  };

  const { findings, skipped } = await runProviders(
    [semgrepProvider, osvProvider, madgeProvider, sccProvider, gitleaksProvider, eslintProvider, testsProvider, firebaseProvider, depsProvider, headersProvider, ciProvider, checkovProvider, hadolintProvider, trivyProvider, banditProvider, gosecProvider, phpstanProvider],
    config,
    ctx,
  );
  // Cross-tool corroboration first (gitleaks ↔ trivy secret overlap), then
  // dedup (dependency CVE merge records corroboration too), then sort.
  const sorted = sortFindings(dedupeFindings(corroborateFindings(findings)));
  // Findings inside test files are reported but NOT scored: test code is not
  // shipped to production, yet a real key committed to a test file is still
  // public in git — so it must be flagged without tanking the readiness score.
  // The `tests` provider's own signal (TD-017, no-tests) stays scored.
  for (const finding of sorted) {
    if (
      finding.kind !== 'dependency' &&
      finding.source.provider !== 'tests' &&
      isTestFile(finding.file)
    ) {
      finding.inTests = true;
    }
  }
  // Dependency CVEs score separately: "upgrade this package" is not the same
  // remediation as "rewrite this code", and the quiz has no dependency axis.
  // Advisory findings (e.g. a secret in a conventional config file) are flagged
  // but not scored — the team's config-placement choice is not a code defect.
  const codeFindings = sorted.filter(
    (finding) => finding.kind !== 'dependency' && !finding.inTests && !finding.advisory,
  );
  const scores = computeScores(codeFindings);
  const dependencies = summarizeDependencies(sorted);

  const { total, max, tier, riskPercentage } = scores;
  const teardownFacts = await listTeardowns();
  const calibration = computeCalibration({
    quiz: config.quiz,
    scanTotal: total,
    scanPillars: scores.pillars,
    findings: codeFindings,
    teardownFacts,
  });

  // Go-live readiness: dependency CVE severity + CI maturity + App Check +
  // disabled checks — the signals the headline score deliberately excludes.
  const readiness = computeReadiness({
    deps: { critical: dependencies.critical, high: dependencies.high },
    ci: {
      noPipeline: hasCiAdvisory(sorted, 'no-pipeline'),
      noTests: hasCiAdvisory(sorted, 'no-tests'),
      noCoverage: hasCiAdvisory(sorted, 'no-coverage'),
    },
    appCheckOff: detectAppCheckOff(options.repoRoot, stack),
    disabledCount: disabled.length,
  });

  const report = /** @type {Report} */ ({
    schemaVersion: 1,
    engine: { name: ENGINE_NAME, version: ENGINE_VERSION, commit: readCommit() },
    generatedAt: new Date().toISOString(),
    riskScore: { total, max, tier, riskPercentage },
    pillars: scores.pillars,
    findings: sorted,
    dependencies,
    skippedProviders: skipped,
    disabledChecks: disabled,
    notStaticallyVerifiable: [],
    stack,
    readiness,
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

/**
 * Normalize a repo-relative path for exclude matching: forward slashes, no
 * trailing slash.
 * @param {string} path
 * @returns {string}
 */
function normalizeRelPath(path) {
  return path.replace(/\\/g, '/').replace(/\/+$/, '');
}

/**
 * Does a repo-relative path match an exclude entry (exact dir or prefix)?
 * `"examples/"` skips the whole `examples/` subtree; `"docs/legacy"` skips just
 * that directory. Both sides are normalized here (forward slashes, no trailing
 * slash), so callers may pass entries verbatim from the config.
 * @param {string[]} excludes — repo-relative entries (e.g. `"examples/"`).
 * @param {string} repoPath — repo-relative path (may carry a trailing slash).
 * @returns {boolean}
 */
export function isExcludedPath(excludes, repoPath) {
  const normalized = normalizeRelPath(repoPath);
  return excludes.some((exclude) => {
    const entry = normalizeRelPath(exclude);
    return normalized === entry || normalized.startsWith(`${entry}/`);
  });
}
