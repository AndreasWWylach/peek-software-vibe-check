// @ts-check
/**
 * @fileoverview Madge provider — circular-dependency detection (architecture graph).
 *
 * Madge builds the module dependency graph and reports import cycles. A cycle
 * is an architectural flaw: two or more modules that depend on each other
 * cannot be reasoned about or tested in isolation — the classic "pattern
 * fragmentation" smell (TD-021). Offline and deterministic (pure static graph).
 */
import { existsSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { commandAvailable, runCommandCapture } from '../proc.mjs';
import { lookupTeardown } from '../catalog.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').ScanConfig} ScanConfig */
/** @typedef {import('../types.mjs').RunContext} RunContext */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */
/** @typedef {import('../catalog.mjs').TeardownFact} TeardownFact */

/** The teardown this provider maps to (architecture graph → pattern fragmentation). */
const TEARDOWN_ID = 'TD-021';

/** Fallbacks when the vendored catalog does not yet carry TD-021. */
const DEFAULTS = {
  pillar: /** @type {Pillar} */ ('architecture'),
  severity: /** @type {Severity} */ ('high'),
  fixSummary: 'Break the import cycle — extract a shared module or invert a dependency.',
};

/** @type {Provider} */
export const madgeProvider = {
  id: 'madge',
  name: 'Madge (architecture graph)',
  available: () => commandAvailable('madge'),
  applicable: (config) =>
    (config.languages ?? []).some((language) => ['javascript', 'typescript'].includes(language)),
  async run(_config, ctx) {
    const targets = ctx.targets.filter((target) => existsSync(target));
    if (targets.length === 0) {
      ctx.log('  no existing targets — nothing to scan');
      return [];
    }

    /** @type {Set<string>} */
    const cycles = new Set();
    for (const target of targets) {
      // `runCommandCapture` because madge exits 1 when cycles are found (the
      // JSON is still written to stdout — mirroring osv-scanner's convention).
      const { stdout } = runCommandCapture(
        'madge',
        ['--circular', '--json', '--no-spinner', '--extensions', 'js,mjs,cjs,jsx,ts,tsx', target],
        { cwd: ctx.repoRoot },
      );
      // Madge reports paths relative to the target; re-anchor them to repoRoot.
      for (const cycle of parseMadgeJson(stdout)) {
        cycles.add(
          cycle
            .map((file) => relative(ctx.repoRoot, resolve(target, file)))
            .sort()
            .join(' → '),
        );
      }
    }

    const fact = await lookupTeardown(TEARDOWN_ID);
    return [...cycles].sort().map((cycle) => toFinding(cycle, fact));
  },
};

/**
 * Parse `madge --circular --json` output into a list of cycles.
 * @param {string} stdout
 * @returns {string[][]} cycles, each an array of module paths (as madge reports them).
 */
export function parseMadgeJson(stdout) {
  const parsed = JSON.parse(stdout);
  const cycles = Array.isArray(parsed) ? parsed : [];
  /** @type {string[][]} */
  const result = [];
  for (const cycle of cycles) {
    if (Array.isArray(cycle) && cycle.length >= 2) {
      result.push(cycle.map((file) => String(file)));
    }
  }
  return result;
}

/**
 * Build a TD-021 finding from a cycle signature.
 * @param {string} signature — e.g. "src/a.ts → src/b.ts" (sorted).
 * @param {TeardownFact | undefined} fact — catalog facts, when vendored.
 * @returns {Finding}
 */
function toFinding(signature, fact) {
  const [file] = signature.split(' → ');
  return {
    id: `madge:${signature}`,
    kind: 'teardown',
    file: file ?? signature,
    line: null,
    column: null,
    severity: fact?.severity ?? DEFAULTS.severity,
    pillar: fact?.pillar ?? DEFAULTS.pillar,
    teardownId: TEARDOWN_ID,
    title: `Circular dependency: ${signature}`,
    message: `Modules import each other in a cycle: ${signature}.`,
    fixSummary: fact?.fixSummary ?? DEFAULTS.fixSummary,
    source: { provider: 'madge', ruleId: 'circular-dependency' },
    dependency: null,
  };
}
