// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Trivy provider — filesystem vulnerability + secret scanning.
 *
 * Trivy is the "second opinion" engine: its secret scanner (which embeds
 * gitleaks' rules) and its vulnerability DB overlap gitleaks + osv-scanner.
 * Rather than treat that overlap as noise, the engine's corroboration layer
 * collapses findings that two engines agree on and annotates them
 * (`corroboratedBy`). See `src/findings.mjs` → `corroborateFindings`.
 *
 * Finding mapping:
 *   - `Vulnerabilities` → `kind: 'dependency'` (merges with osv-scanner by
 *     package+ecosystem, CVE ids unioned).
 *   - `Secrets` → `kind: 'hygiene'`, advisory (gitleaks is the scoring secret
 *     engine; trivy confirms). The secret VALUE is never echoed into findings.
 *
 * Only `vuln` + `secret` scanners run (`--scanners vuln,secret`) — IaC
 * misconfiguration is checkov's job, so Trivy's misconfig scanner is skipped.
 */
import { existsSync, readdirSync, statSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { commandAvailable, runCommandCapture } from '../proc.mjs';
import { IGNORED_DIRS, isEnvFile, isIgnoredDir, isSecretConfigFile } from '../ignore.mjs';
import { readLine, shouldSkipSecret } from '../secretClassify.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */

/** Map trivy severity strings to our shared enum. */
const TRIVY_SEVERITY = /** @type {Record<string, Severity>} */ ({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
});

/** Map trivy package `Type` to OSV-style ecosystem strings (for dedup merge). */
const TRIVY_ECOSYSTEM = /** @type {Record<string, string>} */ ({
  npm: 'npm',
  yarn: 'npm',
  pnpm: 'npm',
  pip: 'PyPI',
  pipenv: 'PyPI',
  poetry: 'PyPI',
  composer: 'Packagist',
  gomod: 'Go',
  gemspec: 'RubyGems',
  bundler: 'RubyGems',
  cargo: 'crates.io',
  pom: 'Maven',
  jar: 'Maven',
  gradle: 'Maven',
  nuget: 'NuGet',
});

/** @type {Provider} */
export const trivyProvider = {
  id: 'trivy',
  name: 'Trivy (vuln + secrets)',
  available: () => commandAvailable('trivy'),
  applicable: () => true,
  async run(_config, ctx) {
    // Quick gate: skip the (potentially DB-downloading) scan when there is
    // nothing to scan — no dependency manifests anywhere.
    if (!hasManifests(ctx.repoRoot, ctx.targets)) {
      ctx.log('  no dependency manifests — skipping');
      return [];
    }

    const skipDirs = [...IGNORED_DIRS].join(',');
    const args = [
      'fs', ctx.repoRoot,
      '--scanners', 'vuln,secret',
      '--format', 'json',
      '--quiet',
      '--skip-dirs', skipDirs,
    ];
    const { stdout } = runCommandCapture('trivy', args);
    return parseTrivyJson(stdout, ctx.repoRoot);
  },
};

/**
 * Parse `trivy fs --format json` into findings.
 * @param {string} stdout
 * @param {string} repoRoot
 * @returns {Finding[]}
 */
export function parseTrivyJson(stdout, repoRoot) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  const results = /** @type {Array<Record<string, any>> | undefined} */ (parsed?.Results);
  if (!Array.isArray(results)) return [];

  /** @type {Finding[]} */
  const findings = [];
  for (const result of results) {
    const target = String(result.Target ?? '');
    const file = relpath(target, repoRoot);
    if (isIgnoredDir(file)) continue;

    const type = String(result.Type ?? '');
    const ecosystem = TRIVY_ECOSYSTEM[type] ?? null;

    for (const vuln of /** @type {Array<Record<string, any>>} */ (result.Vulnerabilities ?? [])) {
      findings.push(vulnFinding(vuln, file, ecosystem));
    }
    for (const secret of /** @type {Array<Record<string, any>>} */ (result.Secrets ?? [])) {
      // Skip public-by-design / inert values (placeholders, alphabet constants,
      // Firebase Auth REST keys) — same classification as gitleaks.
      const line = typeof secret.StartLine === 'number' ? /** @type {number} */ (secret.StartLine) : null;
      const abs = isAbsolute(file) ? file : join(repoRoot, file);
      if (line != null && shouldSkipSecret(readLine(abs, line), abs)) continue;
      findings.push(secretFinding(secret, file));
    }
  }
  return findings;
}

/**
 * A trivy vulnerability → dependency finding (merges with osv-scanner by package).
 * @param {Record<string, any>} vuln
 * @param {string} file — repo-relative lockfile path.
 * @param {string | null} ecosystem
 * @returns {Finding}
 */
function vulnFinding(vuln, file, ecosystem) {
  const cveId = String(vuln.VulnerabilityID ?? 'CVE-unknown');
  const pkgName = String(vuln.PkgName ?? 'unknown');
  const version = vuln.InstalledVersion != null ? String(vuln.InstalledVersion) : null;
  const severity = /** @type {Severity} */ (
    TRIVY_SEVERITY[String(vuln.Severity ?? '').toUpperCase()] ?? 'low'
  );

  return {
    id: `trivy:${cveId}:${pkgName}`,
    kind: 'dependency',
    file,
    line: null,
    column: null,
    severity,
    pillar: 'security',
    teardownId: null,
    title: vuln.Title ? String(vuln.Title) : `${pkgName}: ${cveId}`,
    message: vuln.Description ? String(vuln.Description) : null,
    fixSummary: vuln.FixedVersion ? `Upgrade ${pkgName} beyond ${String(vuln.FixedVersion)}` : null,
    source: { provider: 'trivy', ruleId: cveId },
    dependency: { package: pkgName, version, ecosystem, cveIds: [cveId] },
  };
}

/**
 * A trivy secret → advisory hygiene finding. The secret value is never echoed.
 * @param {Record<string, any>} secret
 * @param {string} file — repo-relative path of the file containing the secret.
 * @returns {Finding}
 */
function secretFinding(secret, file) {
  const ruleId = String(secret.RuleID ?? 'secret');
  const severity = /** @type {Severity} */ (
    TRIVY_SEVERITY[String(secret.Severity ?? '').toUpperCase()] ?? 'medium'
  );
  const line = typeof secret.StartLine === 'number' ? /** @type {number} */ (secret.StartLine) : null;

  // A secret in a conventional config / env file (`.env`, `config/`,
  // `parameters.yaml`, …) is the framework's documented placement — e.g. a
  // single-source-of-truth repo that keeps live config in git (auto-deploy, no
  // staging). Report it as an advisory that respects that choice, rather than
  // a "remove the secret" lecture.
  const configFile = isEnvFile(file) || isSecretConfigFile(file);

  return {
    id: `trivy:${ruleId}:${file}:${line ?? 0}`,
    kind: 'hygiene',
    file,
    line,
    column: null,
    severity,
    pillar: 'security',
    teardownId: null,
    title: configFile ? 'Committed secret in config' : String(secret.Title ?? 'Hardcoded secret'),
    message: `Trivy detected a ${String(secret.Category ?? 'potential')} secret (rule: ${ruleId}).`,
    fixSummary: configFile
      ? 'Conventional secret placement — ensure the repo stays private (or gitignore this file) and rotate the value if the repo was ever public.'
      : 'Remove the hardcoded secret; move it to a secrets manager and rotate it.',
    source: { provider: 'trivy', ruleId },
    dependency: null,
    // gitleaks is the scoring secret engine; trivy confirms (advisory).
    advisory: true,
  };
}

/** Dependency-manifest basenames (any ecosystem). */
const MANIFEST_NAMES = new Set(['package.json', 'composer.json', 'requirements.txt', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'Gemfile', 'pom.xml', 'build.gradle']);

/**
 * Does the repo have any dependency manifest (cheap gate before a scan that
 * may download trivy's vulnerability DB)? Checks the repo root AND the scan
 * targets (monorepos keep manifests in subdirs).
 * @param {string} repoRoot
 * @param {string[]} targets — absolute target paths.
 * @returns {boolean}
 */
function hasManifests(repoRoot, targets) {
  for (const name of MANIFEST_NAMES) {
    if (existsSync(join(repoRoot, name))) return true;
  }
  for (const target of targets) {
    if (containsManifest(target)) return true;
  }
  return false;
}

/**
 * Recursively search a directory for any dependency manifest.
 * @param {string} dir
 * @returns {boolean}
 */
function containsManifest(dir) {
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    return false;
  }
  if (stat.isFile()) return MANIFEST_NAMES.has(dir.split(/[\\/]/).pop() ?? '');
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (isIgnoredDir(entry.name)) continue;
      if (containsManifest(join(dir, entry.name))) return true;
    } else if (MANIFEST_NAMES.has(entry.name)) {
      return true;
    }
  }
  return false;
}

/**
 * Normalize a path to repo-relative (trivy `Target` is usually already relative).
 * @param {string} location
 * @param {string} repoRoot
 * @returns {string}
 */
function relpath(location, repoRoot) {
  if (isAbsolute(location) && location.startsWith(repoRoot)) {
    return location.slice(repoRoot.length).replace(/^[/\\]+/, '');
  }
  return location.replace(/^[/\\]+/, '');
}
