// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Checkov provider — infrastructure-as-code + IAM policy scanning.
 *
 * Checkov is the reference tool for static IaC analysis (Terraform,
 * CloudFormation, Kubernetes, Dockerfile, Serverless, ARM/Bicep). Its AWS IAM
 * checks flag the canonical wildcard smells (`Action: "*"`, `Resource: "*"`).
 *
 * Finding mapping:
 *   - `kind: 'hygiene'` (no Peek teardown — `source.ruleId` = checkov check id).
 *   - `pillar`: `security` by default; `runtime` for Dockerfile/container checks.
 *   - `severity`: checkov's severity when present (checkov 3.x leaves it null in
 *     JSON), else a curated map + name heuristic — IAM privilege checks
 *     (`CKV_AWS_62/63/355`, `CKV2_AWS_40`, `CKV_AWS_286-290`, and the older
 *     `CKV_AWS_109/110/111`) → high, everything else → medium.
 *   - **scored** = CRITICAL/HIGH (the real misconfigs, incl. IAM wildcards);
 *     **advisory** = MEDIUM/LOW (best-practice noise — same precision-over-volume
 *     discipline as every other provider).
 *   - `secrets` framework is skipped — gitleaks owns secrets, and checkov's
 *     secret scan flags illustrative examples (e.g. teardown-catalog fixtures).
 *
 * Terrascan is a *documented* alternative (single Go binary, OPA/Rego-native)
 * but is not wired yet — the provider registry makes adding it a ~30-line
 * provider, and running both would dedupe via `findings.mjs` (docs §5.7).
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { commandAvailable, runCommandCapture } from '../proc.mjs';
import { isIgnoredDir } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */

/** File basenames / extensions that are IaC by name alone (no content read). */
const IAC_NAME_RE =
  /(^Dockerfile(\..*)?$)|(^docker-compose\.(ya?ml)$)|(^compose\.(ya?ml)$)|(\.tf\.json$)|(\.tf$)|(^serverless\.(ya?ml|json)$)|(\.bicep$)|(\.template(\.(json|ya?ml))?$)/i;

/** Extensions whose *content* may mark them as IaC (CloudFormation / K8s). */
const IAC_CONTENT_EXTS = new Set(['.yaml', '.yml', '.json']);

/** CloudFormation marker (AWS template). */
const CFN_RE = /AWSTemplateFormatVersion/;
/** Kubernetes manifest marker: `apiVersion:` + `kind:` + `metadata:` all present. */
const K8S_RE = /\bapiVersion\s*:\s*\S+[\s\S]*\bkind\s*:\s*\S+[\s\S]*\bmetadata\s*:/;

/** Map checkov's severity strings to our shared enum (used only when present). */
const CHECKOV_SEVERITY = /** @type {Record<string, Severity>} */ ({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
});

/**
 * Checkov 3.x JSON omits per-check severity (it is `null`), so findings are
 * ranked by a curated list + name heuristic instead. IAM privilege checks — the
 * `*` wildcard smells and privilege paths — are ranked high and scored; all
 * other checks fall back to medium (advisory). Both current and older checkov
 * ids are kept (checkov has renamed these checks across releases).
 */
const IAM_PRIVILEGE_CHECK_IDS = new Set([
  'CKV_AWS_62', // full "*-*" administrative privileges
  'CKV_AWS_63', // Action: "*"
  'CKV_AWS_355', // Resource: "*" for restrictable actions
  'CKV2_AWS_40', // full IAM privileges
  'CKV_AWS_286', // privilege escalation
  'CKV_AWS_287', // credentials exposure
  'CKV_AWS_288', // data exfiltration
  'CKV_AWS_289', // permissions management / resource exposure
  'CKV_AWS_290', // write access without constraints
  'CKV_AWS_109', 'CKV_AWS_110', 'CKV_AWS_111', // older ids for the same smells
]);
const IAM_PRIVILEGE_NAME_RE =
  /IAM.*(wildcard|privilege|administrative|exfiltration|escalation|permissions management|write access|credentials exposure)/i;

/** @type {Provider} */
export const checkovProvider = {
  id: 'checkov',
  name: 'Checkov (IaC)',
  available: () => commandAvailable('checkov'),
  applicable: () => true,
  async run(_config, ctx) {
    const iacFiles = findIaCFiles(ctx.repoRoot, ctx.targets);
    if (iacFiles.length === 0) {
      ctx.log('  no IaC files detected — skipping');
      return [];
    }

    ctx.log(`  ${iacFiles.length} IaC file(s) — scanning`);
    const { stdout } = runCommandCapture('checkov', buildScanArgs(ctx.repoRoot, iacFiles), { cwd: ctx.repoRoot });
    return parseCheckovJson(stdout, ctx.repoRoot);
  },
};

/**
 * Build targeted checkov args — scan only the discovered IaC files/dirs, never
 * the whole repo root (which would traverse the entire tree, including scaffold
 * IaC shipped by frameworks, and be slow on large repos).
 * Terraform needs directory context (modules), so `.tf` files are scanned via
 * their parent directory; single-file resources (Dockerfile, compose, …) are
 * passed directly via `--file`.
 * @param {string} repoRoot
 * @param {string[]} iacFiles — repo-relative IaC paths.
 * @returns {string[]} checkov CLI args.
 */
export function buildScanArgs(repoRoot, iacFiles) {
  // Secrets scanning is left to gitleaks — checkov's `secrets` framework also
  // flags illustrative examples (e.g. a teardown catalog's fake API keys), so
  // skip it to avoid noise.
  const args = ['--output', 'json', '--quiet', '--skip-framework', 'secrets'];
  /** @type {Set<string>} */
  const tfDirs = new Set();
  for (const file of iacFiles) {
    if (file.endsWith('.tf') || file.endsWith('.tf.json')) {
      tfDirs.add(dirname(file));
    } else {
      args.push('--file', join(repoRoot, file));
    }
  }
  // Keep only the topmost Terraform dirs — a nested dir is already covered by
  // its ancestor's recursive scan, so passing both would double-scan.
  const dirs = [...tfDirs].sort();
  /** @type {string[]} */
  const minimal = [];
  for (const dir of dirs) {
    if (minimal.some((d) => dir === d || dir.startsWith(`${d}/`))) continue;
    minimal.push(dir);
  }
  for (const dir of minimal) {
    args.push('--directory', dir === '.' ? repoRoot : join(repoRoot, dir));
  }
  return args;
}

/**
 * Parse `checkov --output json` into findings.
 * @param {string} stdout
 * @param {string} repoRoot
 * @returns {Finding[]}
 */
export function parseCheckovJson(stdout, repoRoot) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  // checkov 3.x emits a top-level ARRAY of per-framework reports; older/newer
  // paths emit a single `{ results: { failed_checks } }` object. Accept both.
  const failed = Array.isArray(parsed)
    ? parsed.flatMap((el) => /** @type {Array<Record<string, any>>} */ (el?.results?.failed_checks ?? []))
    : /** @type {Array<Record<string, any>>} */ (parsed?.results?.failed_checks ?? []);
  return failed.map((result) => toFinding(result, repoRoot));
}

/**
 * Convert one checkov failed-check into a finding.
 * @param {Record<string, any>} result
 * @param {string} repoRoot
 * @returns {Finding}
 */
function toFinding(result, repoRoot) {
  const checkId = String(result.check_id ?? result.bc_check_id ?? 'checkov');
  const checkName = String(result.check_name ?? checkId);
  // checkov 3.x leaves `severity` null in JSON — use it when present, else fall
  // back to the curated IAM-privilege map (high) and default everything else to
  // medium (advisory). We rank conservatively because we can't see the severity.
  const rawSeverity = String(result.severity ?? '').toUpperCase();
  const isIamPrivilege = IAM_PRIVILEGE_CHECK_IDS.has(checkId) || IAM_PRIVILEGE_NAME_RE.test(checkName);
  const severity = /** @type {Severity} */ (CHECKOV_SEVERITY[rawSeverity] ?? (isIamPrivilege ? 'high' : 'medium'));
  const absolutePath = String(result.file_abs_path ?? result.file_path ?? '');
  const file = absolutePath.startsWith(repoRoot)
    ? absolutePath.slice(repoRoot.length).replace(/^[/\\]+/, '')
    : absolutePath.replace(/^[/\\]+/, '');

  const range = Array.isArray(result.file_line_range) ? result.file_line_range : [];
  const line = typeof range[0] === 'number' ? /** @type {number} */ (range[0]) : null;

  const title = checkName;
  const resource = result.resource ? ` — resource: ${String(result.resource)}` : '';
  const fixSummary = result.guideline ? String(result.guideline) : null;

  // Dockerfile/container checks are runtime-infra posture, not app security.
  const isRuntime = /CKV_DOCKER_|dockerfile|container/i.test(checkId + title);
  const pillar = /** @type {Pillar} */ (isRuntime ? 'runtime' : 'security');

  // Precision over volume: best-practice MEDIUM/LOW checks are advisory; only
  // the provably-dangerous CRITICAL/HIGH misconfigs (incl. IAM wildcards) score.
  const advisory = severity === 'medium' || severity === 'low';

  return {
    id: `checkov:${checkId}:${file}:${line ?? 0}`,
    kind: 'hygiene',
    file,
    line,
    column: null,
    severity,
    pillar,
    teardownId: null,
    title,
    message: `${title}${resource}`,
    fixSummary,
    source: { provider: 'checkov', ruleId: checkId },
    dependency: null,
    advisory,
  };
}

/**
 * Is this file infrastructure-as-code (by name or by content)?
 * @param {string} repoFile — repo-relative path.
 * @param {string | null} content — file text (only needed for yaml/json).
 * @returns {boolean}
 */
export function isIaCFile(repoFile, content = null) {
  const base = repoFile.split(/[\\/]/).pop() ?? '';
  if (IAC_NAME_RE.test(base)) return true;

  const ext = repoFile.slice(repoFile.lastIndexOf('.')).toLowerCase();
  if (!IAC_CONTENT_EXTS.has(ext)) return false;
  if (content === null) return false;
  return CFN_RE.test(content) || K8S_RE.test(content);
}

/**
 * Collect repo-relative IaC file paths under targets + repo root.
 * @param {string} repoRoot
 * @param {string[]} targets — absolute target paths.
 * @returns {string[]} repo-relative paths (deduplicated).
 */
export function findIaCFiles(repoRoot, targets) {
  /** @type {string[]} */
  const out = [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const target of targets) walk(target, repoRoot, out, seen);
  // Root-level IaC (docker-compose.yml, Dockerfile, *.tf) lives outside targets.
  for (const name of ['docker-compose.yml', 'docker-compose.yaml', 'Dockerfile']) {
    const rootFile = join(repoRoot, name);
    if (existsSync(rootFile)) out.push(name);
  }
  return out;
}

/**
 * Walk a directory (or single file target), collecting IaC files.
 * @param {string} dir
 * @param {string} repoRoot
 * @param {string[]} out
 * @param {Set<string>} seen
 */
function walk(dir, repoRoot, out, seen) {
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    return;
  }
  if (stat.isFile()) {
    const repoFile = toRepoFile(dir, repoRoot);
    if (!seen.has(repoFile) && isIaCFile(repoFile, readIfSmall(dir))) {
      seen.add(repoFile);
      out.push(repoFile);
    }
    return;
  }
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (isIgnoredDir(entry.name)) continue;
      walk(abs, repoRoot, out, seen);
    } else {
      const repoFile = toRepoFile(abs, repoRoot);
      if (isIgnoredDir(repoFile)) continue;
      if (seen.has(repoFile)) continue;
      if (isIaCFile(repoFile, readIfSmall(abs))) {
        seen.add(repoFile);
        out.push(repoFile);
      }
    }
  }
}

/**
 * Read a file's text if it is small enough to scan (bounded IO).
 * @param {string} abs — absolute path.
 * @returns {string | null} content, or null when too large / unreadable.
 */
function readIfSmall(abs) {
  try {
    const stat = statSync(abs);
    if (stat.size > 256 * 1024) return null;
    return readFileSync(abs, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Normalize an absolute path to a repo-relative one.
 * @param {string} location
 * @param {string} repoRoot
 * @returns {string}
 */
function toRepoFile(location, repoRoot) {
  if (isAbsolute(location)) {
    return relative(repoRoot, location).replace(/^[/\\]+/, '');
  }
  return location.replace(/^[/\\]+/, '');
}
