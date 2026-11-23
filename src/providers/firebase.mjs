// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Firebase/Firestore security-rules provider (TD-008, Firestore
 * flavor).
 *
 * Firestore's tenant/access boundary is the security rules file — not Prisma
 * `where` clauses. This provider (pure Node, no binary) checks that boundary:
 *   1. Firestore is used but no `firestore.rules` is checked in.
 *   2. The rules allow open read/write (`if true` / unconditional).
 *   3. The rules grant access without requiring `request.auth`.
 *   4. Storage is used but no `storage.rules` is checked in.
 *
 * Gated on scan-time stack detection — never asks the user whether they use
 * Firebase.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { scanRepo } from '../stack.mjs';
import { isIgnoredDir, isTestFile } from '../ignore.mjs';
import { parseRulesScope, scanFirestoreQueries, scanFirestoreWrites, matchScopeRule, matchScopeRules, findCrossFamilyGets } from '../firestore/scope.mjs';

/** @typedef {import('../types.mjs').Provider} Provider */
/** @typedef {import('../types.mjs').Finding} Finding */
/** @typedef {import('../types.mjs').Severity} Severity */
/** @typedef {import('../types.mjs').Pillar} Pillar */

/** The teardown this provider maps to (tenant/access boundary). */
const TEARDOWN_ID = 'TD-008';

/** @type {Provider} */
export const firebaseProvider = {
  id: 'firebase',
  name: 'Firebase/Firestore (security rules)',
  available: () => Promise.resolve(true),
  applicable: () => true,
  async run(_config, ctx) {
    const { markers, rulesFiles, clientFirestore, unauthFunctions } = scanRepo(ctx.repoRoot, ctx.targets);
    const firestore = markers.has('firestore');
    const storage = markers.has('storage');
    const cloudFunctions = markers.has('cloudFunctions');

    if (!firestore && !storage && !cloudFunctions) {
      return []; // not a Firebase app — nothing to check.
    }

    /** @type {Finding[]} */
    const findings = [];

    if (firestore) {
      const rulesFile = rulesFiles.get('firestore.rules') ?? null;
      if (!rulesFile) {
        // Client SDK direct access + no rules in repo = the boundary is either
        // missing (test mode), unverifiable out-of-band, or maintained in a
        // sibling repo of a shared Firebase project (common suite layout).
        // Server-only (Admin SDK) access has no client boundary, so it's a
        // softer signal.
        findings.push(missingRulesFinding('Firestore', clientFirestore ? 'critical' : 'medium', clientFirestore));
      } else {
        const content = readFileSafely(join(ctx.repoRoot, rulesFile));
        if (isOpenRules(content)) {
          findings.push(openRulesFinding(rulesFile, 'critical'));
        } else if (!requiresAuth(content)) {
          findings.push(noAuthFinding(rulesFile, 'high'));
        }
        // Query side: cross-check client reads against the rule-required scope
        // (the rule/query mismatch class this engine was built to catch).
        for (const mismatch of crossCheckQueries(ctx, content)) {
          findings.push(ruleQueryMismatchFinding(mismatch));
        }
        // Write side: client writes to collections the rules deny are dead code
        // today and a rules-loosening away from client-writable money/inventory.
        for (const denied of crossCheckWrites(ctx, content)) {
          findings.push(writeDeniedFinding(denied));
        }
        // Fence side: in a multi-product rules file, a block that reads another
        // product's collections is an advisory (the static half of the
        // cross-product negative tests the owning repo's harness enforces).
        for (const fence of findCrossFamilyGets(content)) {
          findings.push(crossFamilyFinding(fence));
        }
      }
    }

    if (storage) {
      // A shared project can have one rules file per bucket (`storage.rules`,
      // `storage.rvmedia.rules`, ...) - check every one of them.
      const storageFiles = [...rulesFiles.keys()].filter((k) => /^storage\..*\.rules$/.test(k)).sort();
      if (storageFiles.length === 0) {
        findings.push(missingRulesFinding('Storage', 'medium', false));
      } else {
        for (const file of storageFiles) {
          const relPath = /** @type {string} */ (rulesFiles.get(file));
          const content = readFileSafely(join(ctx.repoRoot, relPath));
          if (isOpenRules(content)) {
            findings.push(openRulesFinding(file, 'critical'));
          } else if (!requiresAuth(content)) {
            findings.push(noAuthFinding(file, 'high'));
          }
        }
      }
    }

    if (cloudFunctions) {
      for (const file of unauthFunctions) {
        findings.push(noHandlerAuthFinding(file));
      }
    }

    return findings;
  },
};

/**
 * Does the rules content grant access unconditionally?
 *
 * Precision first: open WRITES are never acceptable (scoped or not), and an
 * unconditional `allow read;` / `allow write;` / `allow read, write;` is open.
 * A scoped `allow read: if true` (e.g. a public catalog or public reviews, with
 * `write: if false`) is a deliberate, common pattern — NOT flagged.
 * @param {string} text
 * @returns {boolean}
 */
export function isOpenRules(text) {
  return (
    // Open writes (`allow … write … if true`), anywhere.
    /\ballow\s+[^;\n]*\bwrite\b[^;\n]*\bif\s+true\b/.test(text) ||
    // Unconditional allow (no `if` condition at all).
    /\ballow\s+(?:read|write)(\s*,\s*(?:read|write))?\s*;/.test(text)
  );
}

/**
 * Does the rules content require authentication (`request.auth`)?
 * @param {string} text
 * @returns {boolean}
 */
export function requiresAuth(text) {
  return /\brequest\.auth\b/.test(text);
}

/**
 * "No security rules checked in" finding.
 * @param {string} service — "Firestore" or "Storage".
 * @param {Severity} severity
 * @param {boolean} clientDirect — the client SDK accesses the data directly.
 * @returns {Finding}
 */
function missingRulesFinding(service, severity, clientDirect) {
  const name = service === 'Firestore' ? 'firestore.rules' : 'storage.rules';
  const message = clientDirect
    ? `The frontend reads/writes ${service} directly via the client SDK, but no \`${name}\` is checked in — the access-control boundary is unverifiable (test-mode rules, console-managed rules, or rules maintained in a sibling repo of a shared Firebase project).`
    : `No \`${name}\` file is checked in. If all ${service} access is server-side (Admin SDK), the boundary lives in the function code — verify every function authenticates its caller. For a shared Firebase project, the rules may live in a sibling repo.`;
  return {
    id: `firebase:missing-${name}`,
    kind: 'teardown',
    file: name,
    line: null,
    column: null,
    severity,
    pillar: 'security',
    teardownId: TEARDOWN_ID,
    title: `${service} has no security rules`,
    message,
    fixSummary: `Add \`${name}\` requiring \`request.auth\` and tenant-scoped paths, then deploy it via firebase.json — or route all data access through authenticated Cloud Functions. For a shared project, keep the fenced per-product rules section in the sibling repo that deploys them, and verify it covers this app's collections.`,
    source: { provider: 'firebase', ruleId: 'missing-rules' },
    dependency: null,
  };
}

/**
 * "Rules allow open read/write" finding.
 * @param {string} rulesFile
 * @param {Severity} severity
 * @returns {Finding}
 */
function openRulesFinding(rulesFile, severity) {
  return {
    id: `firebase:open-rules:${rulesFile}`,
    kind: 'teardown',
    file: rulesFile,
    line: null,
    column: null,
    severity,
    pillar: 'security',
    teardownId: TEARDOWN_ID,
    title: 'Firestore rules allow open read/write',
    message: 'The rules grant access unconditionally (`if true` or no condition) — any client can read and write every document.',
    fixSummary: 'Restrict every match to `request.auth` plus tenant scoping (`/tenants/{tenantId}/…`), and grant only the needed operations.',
    source: { provider: 'firebase', ruleId: 'open-rules' },
    dependency: null,
  };
}

/**
 * "Rules don't require authentication" finding.
 * @param {string} rulesFile
 * @param {Severity} severity
 * @returns {Finding}
 */
function noAuthFinding(rulesFile, severity) {
  return {
    id: `firebase:no-auth:${rulesFile}`,
    kind: 'teardown',
    file: rulesFile,
    line: null,
    column: null,
    severity,
    pillar: 'security',
    teardownId: TEARDOWN_ID,
    title: 'Firestore rules do not require authentication',
    message: 'The rules grant access without checking `request.auth` — anonymous clients can read or write.',
    fixSummary: 'Require `request.auth != null` (and tenant scoping) on every `match`.',
    source: { provider: 'firebase', ruleId: 'no-auth' },
    dependency: null,
  };
}

/**
 * Cloud Function handler with no visible auth check (TD-032, heuristic).
 * @param {string} file
 * @returns {Finding}
 */
function noHandlerAuthFinding(file) {
  return {
    id: `firebase:handler-no-auth:${file}`,
    kind: 'teardown',
    file,
    line: null,
    column: null,
    severity: 'low',
    pillar: 'security',
    teardownId: 'TD-032',
    title: 'Cloud Function handler with no visible auth check',
    message: 'This file defines `onCall`/`onRequest` handlers but references no auth verification (`request.auth`, `verifyIdToken`, …) — verify it is intentionally public or gated another way (signed URLs, allowlists).',
    fixSummary: 'Verify the caller with `context.auth` / `request.auth` or an explicit token check before touching data.',
    source: { provider: 'firebase', ruleId: 'handler-no-auth' },
    dependency: null,
  };
}

/**
 * Read a file's content, tolerating a missing/unreadable file (returns '').
 * @param {string} file
 * @returns {string}
 */
function readFileSafely(file) {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return '';
  }
}

/** Client source extensions scanned for Firestore queries. */
const CLIENT_EXTS = /\.(ts|tsx|js|mjs|cjs)$/i;

/**
 * Recursively collect client source files under a directory (skips ignored
 * dirs and test files — rule emulator tests deliberately run denied queries).
 * @param {string} dir
 * @param {string} repoRoot
 * @param {Set<string>} out - absolute paths, appended in place.
 */
function collectClientFiles(dir, repoRoot, out) {
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
      collectClientFiles(abs, repoRoot, out);
    } else if (entry.isFile() && CLIENT_EXTS.test(entry.name)) {
      const repoFile = relative(repoRoot, abs).replace(/^[/\\]+/, '');
      if (!isTestFile(repoFile)) out.add(abs);
    }
  }
}

/**
 * Cross-check every client read query against the rule-required scope fields.
 * @param {import('../types.mjs').RunContext} ctx
 * @param {string} rulesText
 * @returns {Array<{ file: string, pathKey: string, alternatives: string[][], line: number }>}
 */
function crossCheckQueries(ctx, rulesText) {
  const scope = parseRulesScope(rulesText);
  if (scope.size === 0) return [];

  /** @type {Set<string>} */
  const files = new Set();
  for (const target of ctx.targets) collectClientFiles(target, ctx.repoRoot, files);

  /** @type {Array<{ file: string, pathKey: string, alternatives: string[][], line: number }>} */
  const mismatches = [];
  for (const abs of files) {
    const source = readFileSafely(abs);
    if (!source) continue;
    const repoFile = relative(ctx.repoRoot, abs).replace(/^[/\\]+/, '');
    for (const query of scanFirestoreQueries(source)) {
      if (!query.read) continue;
      const rule = matchScopeRule(scope, query.pathKey);
      if (!rule || !rule.requiresAuth || rule.branches.length === 0) continue;
      // A query satisfies the rule when it constrains by every field of at
      // least one branch (an empty branch needs nothing - e.g. `uid()`-only).
      const satisfied = rule.branches.some((branch) =>
        branch.every((field) => query.whereFields.has(field)));
      if (!satisfied) {
        mismatches.push({ file: repoFile, pathKey: query.pathKey, alternatives: rule.branches, line: query.line });
      }
    }
  }
  return mismatches;
}

/**
 * Cross-check every client-side Firestore WRITE against the rules: a write to
 * a collection whose rules deny client writes (deny-by-default, `allow write:
 * if false`) can never succeed - or worse, someone loosened the rules to make
 * it succeed. Server-side Admin SDK code (functions/) is exempt: it bypasses
 * rules by design.
 * @param {import('../types.mjs').RunContext} ctx
 * @param {string} rulesText
 * @returns {Array<{ file: string, pathKey: string, line: number }>}
 */
function crossCheckWrites(ctx, rulesText) {
  const scope = parseRulesScope(rulesText);
  if (scope.size === 0) return [];

  /** @type {Set<string>} */
  const files = new Set();
  for (const target of ctx.targets) collectClientFiles(target, ctx.repoRoot, files);

  /** @type {Array<{ file: string, pathKey: string, line: number }>} */
  const denied = [];
  for (const abs of files) {
    const repoFile = relative(ctx.repoRoot, abs).replace(/^[/\\]+/, '');
    if (isServerFile(repoFile)) continue;
    const source = readFileSafely(abs);
    if (!source || /firebase-admin|firebase-functions/.test(source)) continue;
    for (const write of scanFirestoreWrites(source)) {
      if (!write.pathKey || write.pathKey.split('/').every((seg) => seg === '*')) continue;
      const rules = matchScopeRules(scope, write.pathKey);
      // Deny-by-default: no matching rule also denies the write.
      if (rules.every((rule) => rule.writesDenied)) {
        denied.push({ file: repoFile, pathKey: write.pathKey, line: write.line });
      }
    }
  }
  return denied;
}

/**
 * Is a repo-relative file server-side (a Cloud Functions workspace)?
 * @param {string} repoFile
 * @returns {boolean}
 */
function isServerFile(repoFile) {
  return repoFile.split(/[/\\]/).includes('functions');
}

/**
 * "Client writes to a rules-denied collection" finding.
 * @param {{ file: string, pathKey: string, line: number }} denied
 * @returns {Finding}
 */
function writeDeniedFinding(denied) {
  const { file, pathKey, line } = denied;
  return {
    id: `firebase:write-denied:${file}:${pathKey}`,
    kind: 'teardown',
    file,
    line,
    column: null,
    severity: 'high',
    pillar: 'security',
    teardownId: TEARDOWN_ID,
    title: `Client writes to \`${pathKey}\`, which the rules deny`,
    message: `This client-side write targets \`${pathKey}\`, but \`firestore.rules\` denies client writes there (\`allow write: if false\` or no write rule). Denied writes fail at runtime - and if the rules were ever loosened to make this work, the client would be writing data the design reserves for Cloud Functions (money and inventory must move only inside authenticated function transactions).`,
    fixSummary: 'Move the write into an authenticated Cloud Function (Admin SDK), or add a scoped `allow write` rule and constrain the client by it.',
    source: { provider: 'firebase', ruleId: 'write-denied' },
    dependency: null,
  };
}

/**
 * "Rule reads another product's collections" advisory (cross-product fence).
 * @param {{ blockPath: string, foreign: string[] }} fence
 * @returns {Finding}
 */
function crossFamilyFinding(fence) {
  const { blockPath, foreign } = fence;
  const shortPath = blockPath.replace(/^\/databases\/\{[^}]+\}\/documents\//, '');
  return {
    id: `firebase:cross-family-get:${blockPath}`,
    kind: 'hygiene',
    file: 'firestore.rules',
    line: null,
    column: null,
    severity: 'medium',
    pillar: 'security',
    teardownId: null,
    title: `Rule on \`${shortPath}\` reads another product's collections`,
    message: `This match block reaches \`${foreign.join('`, `')}\`, which belong to a different collection family - in a multi-product rules file, fenced sections must not read across products (or grant access that crosses them).`,
    fixSummary: 'Route the cross-product read through a shared helper the owning product exposes, or confirm the fence boundary is intentional.',
    source: { provider: 'firebase', ruleId: 'cross-family-get' },
    dependency: null,
    advisory: true,
  };
}

/**
 * "Client query does not constrain by the rule-required scope field" finding.
 * @param {{ file: string, pathKey: string, alternatives: string[][], line: number }} mismatch
 * @returns {Finding}
 */
function ruleQueryMismatchFinding(mismatch) {
  const { file, pathKey, alternatives, line } = mismatch;
  const options = alternatives
    .filter((branch) => branch.length > 0)
    .map((branch) => branch.join('`, `'));
  const description = options.length > 0 ? options.join('` OR `') : 'the rule-required scope';
  const first = alternatives.find((branch) => branch.length > 0) ?? [];
  return {
    id: `firebase:rule-query-mismatch:${file}:${pathKey}`,
    kind: 'teardown',
    file,
    line,
    column: null,
    severity: 'high',
    pillar: 'security',
    teardownId: TEARDOWN_ID,
    title: `Firestore query on \`${pathKey}\` misses the rule-required scope`,
    message: `This read query on \`${pathKey}\` does not constrain by \`${description}\`, which \`firestore.rules\` requires — the query fails permission checks (or would read across tenants if the rule were looser).`,
    fixSummary: `Add \`where('${first[0]}', '==', uid)\` (or one of the rule's alternatives) to the query so it satisfies the rule, or route the read through an authenticated Cloud Function.`,
    source: { provider: 'firebase', ruleId: 'rule-query-mismatch' },
    dependency: null,
  };
}
