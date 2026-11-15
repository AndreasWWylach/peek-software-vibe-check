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
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { detectStack, findRulesFile } from '../stack.mjs';

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
    const stack = detectStack(ctx.repoRoot, ctx.targets);
    if (!stack.firestore && !stack.storage) {
      return []; // not a Firebase data app — nothing to check.
    }

    /** @type {Finding[]} */
    const findings = [];

    if (stack.firestore) {
      const rulesFile = findRulesFile(ctx.repoRoot, ctx.targets, 'firestore.rules');
      if (!rulesFile) {
        findings.push(missingRulesFinding('Firestore', 'high'));
      } else {
        const content = readFileSafely(join(ctx.repoRoot, rulesFile));
        if (isOpenRules(content)) {
          findings.push(openRulesFinding(rulesFile, 'critical'));
        } else if (!requiresAuth(content)) {
          findings.push(noAuthFinding(rulesFile, 'high'));
        }
      }
    }

    if (stack.storage) {
      const rulesFile = findRulesFile(ctx.repoRoot, ctx.targets, 'storage.rules');
      if (!rulesFile) {
        findings.push(missingRulesFinding('Storage', 'medium'));
      }
    }

    return findings;
  },
};

/**
 * Does the rules content grant access unconditionally (`if true` / no condition)?
 * @param {string} text
 * @returns {boolean}
 */
export function isOpenRules(text) {
  return (
    /\ballow\b[^;\n]*\bif\s+true\b/.test(text) ||
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
 * @returns {Finding}
 */
function missingRulesFinding(service, severity) {
  const name = service === 'Firestore' ? 'firestore.rules' : 'storage.rules';
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
    message: `The app uses ${service} but no \`${name}\` file is checked in — the data may be open to unauthenticated read/write.`,
    fixSummary: `Add \`${name}\` requiring \`request.auth\` and tenant-scoped paths, then deploy it via firebase.json.`,
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
