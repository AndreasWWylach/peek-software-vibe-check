// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Dependency-hygiene provider — LastMile "Hardener" framework.
 *
 * Two deterministic, offline facts about how the repo declares dependencies:
 *
 *   1. **Missing lockfile** — a manifest exists but no lockfile pins the
 *      transitive graph, so builds are not reproducible and supply-chain
 *      attacks can slip in via the resolver. (medium, runtime)
 *   2. **Floating version** — a dependency is declared with an unbounded or
 *      moving version (`*`, `latest`, `dev-master`, `>=x` with no upper bound,
 *      a bare requirement, …). (low, runtime)
 *
 * Caret/tilde ranges (`^1.2.3`, `~1.2`) are NOT flagged: they are semver-
 * constrained with an implied upper bound and are the ecosystem default.
 * This keeps the check a precise signal rather than noise.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { isIgnoredDir } from '../ignore.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */

/**
 * Manifest basename → the lockfiles that pin it. A manifest is "pinned" when
 * any listed lockfile sits in the same directory (checked with `existsSync`).
 */
const MANIFEST_LOCKFILES = new Map([
  ['package.json', ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb']],
  ['composer.json', ['composer.lock']],
  ['Gemfile', ['Gemfile.lock']],
  ['Pipfile', ['Pipfile.lock']],
  ['pyproject.toml', ['poetry.lock', 'uv.lock']],
  ['Cargo.toml', ['Cargo.lock']],
  ['go.mod', ['go.sum']],
]);

/**
 * `requirements.txt` has no lockfile concept — its lines ARE the pins (or not).
 * It is handled in the floating-version pass only.
 */
const REQUIREMENTS = 'requirements.txt';

/** Dependency maps in `package.json` whose string values are version ranges. */
const NPM_DEP_KEYS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

/** Dependency maps in `composer.json` whose string values are version ranges. */
const COMPOSER_DEP_KEYS = ['require', 'require-dev'];

/**
 * Does this manifest actually declare any dependencies? A scripts-only
 * `package.json` (a monorepo root) has nothing to pin, so a missing lockfile
 * there is not a gap.
 * @param {string} base
 * @param {string} content
 * @returns {boolean}
 */
export function declaresDependencies(base, content) {
  if (base === 'package.json' || base === 'composer.json') {
    const keys = base === 'package.json' ? NPM_DEP_KEYS : COMPOSER_DEP_KEYS;
    try {
      const manifest = JSON.parse(content);
      return keys.some((key) => {
        const deps = manifest[key];
        return deps && typeof deps === 'object' && Object.keys(deps).length > 0;
      });
    } catch {
      return true; // unparseable — do not suppress the lockfile check
    }
  }
  return true;
}

/** Unconditionally-moving npm versions (`*`, `latest`, URL/git/file refs, …). */
const FLOATING_NPM_RE = /^(\*|latest|next|dev|x|file:|link:|git:|git\+|https?:|workspace:|npm:)/i;

/** @type {Provider} */
export const depsProvider = {
  id: 'deps',
  name: 'Dependency hygiene',
  // Pure file reading — no binary to install, always available.
  available: () => Promise.resolve(true),
  applicable: () => true,
  async run(_config, ctx) {
    /** @type {string[]} */
    const seen = [];
    // Manifests live at package boundaries (repo root + workspace subdirs), not
    // inside source targets — walk the whole repo, skipping ignored dirs.
    collectFiles(ctx.repoRoot, ctx.repoRoot, seen);
    // Deduplicate (overlapping targets) and keep only known manifests.
    const manifests = [...new Set(seen)].filter((file) => {
      const base = file.split(/[\\/]/).pop() ?? '';
      return MANIFEST_LOCKFILES.has(base) || base === REQUIREMENTS;
    });

    /** @type {Finding[]} */
    const findings = [];
    let missingLockfiles = 0;
    let floating = 0;

    for (const repoFile of manifests) {
      const base = repoFile.split(/[\\/]/).pop() ?? '';
      const abs = join(ctx.repoRoot, repoFile);
      let content = '';
      try {
        content = readFileSync(abs, 'utf8');
      } catch {
        continue;
      }

      if (base !== REQUIREMENTS && declaresDependencies(base, content)) {
        const lockfiles = MANIFEST_LOCKFILES.get(base) ?? [];
        const hasLockfile = lockfiles.some((lock) => existsSync(join(dirname(abs), lock)));
        // A monorepo may keep one lockfile at the root while package.json files
        // live in workspace subdirs — walk up to the repo root before judging.
        const rootLocked = lockfiles.some((lock) => existsSync(join(ctx.repoRoot, lock)));
        if (!hasLockfile && !rootLocked) {
          missingLockfiles += 1;
          findings.push(missingLockfileFinding(repoFile, base));
        }
      }

      floating += collectFloating(repoFile, base, content, findings);
    }

    ctx.log(`  ${manifests.length} manifest(s), ${missingLockfiles} missing lockfile(s), ${floating} floating version(s)`);
    return findings;
  },
};

/**
 * Detect floating (unpinned) dependency declarations and append findings.
 * @param {string} repoFile — repo-relative manifest path.
 * @param {string} base — manifest basename (drives the parser).
 * @param {string} content — manifest text.
 * @param {Finding[]} out — appended to.
 * @returns {number} number of floating declarations found.
 */
function collectFloating(repoFile, base, content, out) {
  let count = 0;
  if (base === 'package.json') {
    count += scanJsonManifest(repoFile, base, content, NPM_DEP_KEYS, isFloatingNpm, () => false, out);
  } else if (base === 'composer.json') {
    // Platform requirements (php, ext-*, lib-*, composer-*) are conventionally
    // declared as `>=x` / `*` and are not supply-chain pins — skip them.
    count += scanJsonManifest(repoFile, base, content, COMPOSER_DEP_KEYS, isFloatingComposer, isComposerPlatformPackage, out);
  } else if (base === REQUIREMENTS) {
    count += scanRequirements(repoFile, content, out);
  }
  return count;
}

/**
 * Scan a JSON manifest's dependency maps for floating values.
 * @param {string} repoFile
 * @param {string} base
 * @param {string} content
 * @param {string[]} depKeys
 * @param {(version: string) => boolean} isFloating
 * @param {(name: string) => boolean} skipName — platform requirements to skip.
 * @param {Finding[]} out
 * @returns {number}
 */
function scanJsonManifest(repoFile, base, content, depKeys, isFloating, skipName, out) {
  let data;
  try {
    data = JSON.parse(content);
  } catch {
    return 0;
  }
  const lines = content.split('\n');
  let count = 0;
  for (const key of depKeys) {
    const deps = /** @type {Record<string, string> | undefined} */ (data?.[key]);
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, version] of Object.entries(deps)) {
      if (typeof version !== 'string') continue;
      if (skipName(name)) continue;
      if (!isFloating(version)) continue;
      count += 1;
      out.push(floatingFinding(repoFile, name, version, lineOf(lines, `"${name}"`)));
    }
  }
  return count;
}

/**
 * Scan a `requirements.txt`-style file line by line.
 * @param {string} repoFile
 * @param {string} content
 * @param {Finding[]} out
 * @returns {number}
 */
function scanRequirements(repoFile, content, out) {
  const lines = content.split('\n');
  let count = 0;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const spec = line.split(/\s*#/)[0].trim();
    if (!spec) continue;
    if (!isFloatingRequirement(spec)) continue;
    const name = spec.split(/[<>=~!*[\s]/)[0].trim();
    if (!name) continue;
    count += 1;
    out.push(floatingFinding(repoFile, name, spec, index + 1));
  }
  return count;
}

/**
 * Is an npm version range floating (unbounded or moving)?
 * @param {string} version
 * @returns {boolean}
 */
export function isFloatingNpm(version) {
  const trimmed = version.trim();
  if (FLOATING_NPM_RE.test(trimmed)) return true;
  // Unbounded range: `>=` / `>` with no upper bound.
  if (/^[>=]/.test(trimmed) && !trimmed.includes('<')) return true;
  return false;
}

/**
 * Is a composer version constraint floating (unbounded or a branch alias)?
 * @param {string} version
 * @returns {boolean}
 */
export function isFloatingComposer(version) {
  const trimmed = version.trim();
  if (/^(\*|dev-)/i.test(trimmed)) return true;
  if (/^[>=]/.test(trimmed) && !trimmed.includes('<')) return true;
  return false;
}

/**
 * Is this a Composer platform requirement (PHP/extension/lib), conventionally
 * declared as `>=x` or `*` and not a supply-chain pin?
 * @param {string} name
 * @returns {boolean}
 */
export function isComposerPlatformPackage(name) {
  return /^(php|hhvm|ext-.*|lib-.*|composer(-plugin-api|-runtime-api)?)$/i.test(name);
}

/**
 * Is a `requirements.txt` spec floating (no pin, or unbounded lower bound)?
 * @param {string} spec — e.g. `flask==2.0`, `flask>=2.0`, `flask`.
 * @returns {boolean}
 */
export function isFloatingRequirement(spec) {
  const trimmed = spec.trim();
  if (/^[=~]/.test(trimmed)) return false;
  if (trimmed.includes('==') || trimmed.includes('~=')) return false;
  // `>=` / `>` with an upper bound (`>=2.0,<3`) is bounded.
  if (/[>=]/.test(trimmed) && trimmed.includes('<')) return false;
  // A bare name (no comparator) is unpinned.
  return true;
}

/**
 * 1-based line number of `needle` in `lines`, or null when absent.
 * @param {string[]} lines
 * @param {string} needle
 * @returns {number | null}
 */
function lineOf(lines, needle) {
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].includes(needle)) return index + 1;
  }
  return null;
}

/**
 * The "missing lockfile" finding.
 * @param {string} repoFile
 * @param {string} base
 * @returns {Finding}
 */
function missingLockfileFinding(repoFile, base) {
  return {
    id: `deps:${repoFile}:no-lockfile`,
    kind: 'hygiene',
    file: repoFile,
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'runtime',
    teardownId: null,
    title: `No lockfile pins ${base} dependencies`,
    message: `Dependencies are declared in ${base} but no lockfile was found — builds are not reproducible and a malicious or compromised release can slip in through the resolver.`,
    fixSummary: 'Commit the lockfile (npm/yarn/pnpm/composer/…) and install with --frozen-lockfile / composer install in CI.',
    source: { provider: 'deps', ruleId: 'no-lockfile' },
    dependency: null,
  };
}

/**
 * The "floating version" finding.
 * @param {string} repoFile
 * @param {string} name
 * @param {string} version
 * @param {number | null} line
 * @returns {Finding}
 */
function floatingFinding(repoFile, name, version, line) {
  return {
    id: `deps:${repoFile}:${name}:floating`,
    kind: 'hygiene',
    file: repoFile,
    line,
    column: null,
    severity: 'low',
    pillar: 'runtime',
    teardownId: null,
    title: `Dependency "${name}" uses a floating version`,
    message: `"${name}" is declared as "${version}" — an unbounded or moving range. Pin it to a specific version (or a caret/tilde range with an upper bound) so upgrades are explicit and reviewed.`,
    fixSummary: `Pin "${name}" to an exact version or a bounded range (e.g. ^x.y.z), then re-lock.`,
    source: { provider: 'deps', ruleId: 'floating-version' },
    dependency: null,
    // Advisory: `*` / unbounded ranges are a policy judgment, not a proven code
    // defect (same rationale as committed config secrets) — report, don't score.
    advisory: true,
  };
}

/**
 * Recursively collect repo-relative file paths under `dir`, skipping junk dirs
 * and non-code/data files (kept for manifests: json/txt/toml/lock are NOT
 * code, but are exactly what we read — so we collect them here).
 * @param {string} dir — absolute directory.
 * @param {string} repoRoot
 * @param {string[]} out — accumulates repo-relative paths.
 */
function collectFiles(dir, repoRoot, out) {
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    return;
  }
  // A file target (e.g. a single manifest path) — collect it directly.
  if (stat.isFile()) {
    const repoFile = toRepoFile(dir, repoRoot);
    const base = repoFile.split(/[\\/]/).pop()?.toLowerCase() ?? '';
    if (MANIFEST_LOCKFILES.has(base) || base === REQUIREMENTS) out.push(repoFile);
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
      collectFiles(abs, repoRoot, out);
    } else if (entry.isFile()) {
      const repoFile = toRepoFile(abs, repoRoot);
      const base = entry.name.toLowerCase();
      if (isIgnoredDir(repoFile)) continue;
      if (!(MANIFEST_LOCKFILES.has(base) || base === REQUIREMENTS)) continue;
      out.push(repoFile);
    }
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
