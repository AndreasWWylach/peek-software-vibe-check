// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Firestore rule/query scope cross-check (TD-008, Firestore flavor).
 *
 * Firestore's tenant/ownership boundary lives in `firestore.rules`, not in a
 * database column. The shipped reelvenue bug was the mismatch side: a rule
 * correctly required `ownerUid`, but the client query did not constrain by it.
 *
 * Two halves:
 *   1. `parseRulesScope` — extract, per `match` path, the auth-scope fields the
 *      READ rules require (`resource.data.get('ownerUid', '') == uid()`).
 *   2. `scanFirestoreQueries` — find client Firestore read queries and the
 *      `where(...)` fields they constrain by.
 *
 * A query is a finding only when its collection path is governed by a rule that
 * REQUIRES auth on every read AND names a scope field the query never filters.
 * Public collections (an `allow read: if …` with no `request.auth`) are skipped.
 */

/**
 * @typedef {Object} FirestoreScopeRule
 * @property {Set<string>} required — auth-scope fields the read rules name.
 * @property {boolean} requiresAuth — every read rule references `request.auth` / `uid()`.
 */

/** @typedef {Map<string, FirestoreScopeRule>} RulesScope */

/**
 * Parse `firestore.rules` into a path → scope map.
 *
 * @param {string} text — full rules file text.
 * @returns {RulesScope} key = literal path segments joined by `/` (wildcards dropped).
 */
export function parseRulesScope(text) {
  /** @type {Map<string, FirestoreScopeRule>} */
  const scope = new Map();
  /** @type {Array<{ path: string, openDepth: number, readLines: string[] }>} */
  const stack = [];
  let depth = 0;

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    const match = /^match\s+(\/\S+)\s*\{/.exec(trimmed);
    if (match) {
      const relPath = match[1].trim();
      const parent = stack.length > 0 ? stack[stack.length - 1].path : '';
      const fullPath = (parent + '/' + relPath).replace(/\/{2,}/g, '/');
      stack.push({ path: fullPath, openDepth: depth, readLines: [] });
    } else if (/^allow\s+(?:read|get|list)\b/.test(trimmed) && stack.length > 0) {
      stack[stack.length - 1].readLines.push(trimmed);
    }

    depth += countChar(line, '{') - countChar(line, '}');

    while (stack.length > 0 && depth <= stack[stack.length - 1].openDepth) {
      const block = stack.pop();
      if (!block) continue;
      const rule = toScopeRule(block.readLines);
      if (rule) scope.set(pathKey(block.path), rule);
    }
  }

  return scope;
}

/**
 * Derive a scope rule from a match block's read lines — null when the block has
 * no reads, or has a public read (so the collection is not auth-gated).
 * @param {string[]} readLines
 * @returns {FirestoreScopeRule | null}
 */
function toScopeRule(readLines) {
  if (readLines.length === 0) return null;
  const allAuth = readLines.every((line) => /(?:uid\(\)|request\.auth)/.test(line));
  if (!allAuth) return null; // a public read exists — no blanket auth scope to enforce
  /** @type {Set<string>} */
  const required = new Set();
  for (const line of readLines) {
    for (const field of extractScopeFields(line)) required.add(field);
  }
  return { required, requiresAuth: true };
}

/**
 * Extract `resource.data.*` field names a read rule compares to auth.
 * @param {string} line
 * @returns {string[]}
 */
function extractScopeFields(line) {
  /** @type {Set<string>} */
  const fields = new Set();
  const getRe = /resource\.data\.get\(\s*'([^']+)'/g;
  // Dot access to a field — skip method calls (`resource.data.size()`, …):
  // a field read is never followed by `(`.
  const dotRe = /resource\.data\.(?!\w+\()([A-Za-z_][A-Za-z0-9_]*)/g;
  let m;
  while ((m = getRe.exec(line))) fields.add(m[1]);
  while ((m = dotRe.exec(line))) fields.add(m[1]);
  return [...fields];
}

/**
 * Normalize a match path to its literal segment key: drop the
 * `/databases/{database}/documents` root and any `{wildcard}` segment.
 * @param {string} path
 * @returns {string}
 */
function pathKey(path) {
  const segments = path.split('/').filter(Boolean);
  const docsIdx = segments.findIndex((segment) => segment === 'documents');
  const rest = docsIdx >= 0 ? segments.slice(docsIdx + 1) : segments;
  return rest.filter((segment) => !segment.startsWith('{')).join('/');
}

/**
 * Count a character in a string.
 * @param {string} text
 * @param {string} char
 * @returns {number}
 */
function countChar(text, char) {
  let count = 0;
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === char) count += 1;
  }
  return count;
}

/** @typedef {{ pathKey: string, whereFields: Set<string>, read: boolean, line: number }} FirestoreQuery */

/**
 * Find Firestore client queries in one source file (Firebase v9 modular SDK).
 *
 * @param {string} source
 * @returns {FirestoreQuery[]}
 */
export function scanFirestoreQueries(source) {
  /** @type {FirestoreQuery[]} */
  const queries = [];
  const collectionRe = /collection\(\s*/g;
  let m;
  while ((m = collectionRe.exec(source))) {
    const start = m.index + m[0].length;
    // Bound the scan to the enclosing statement (up to the next `;`) so a
    // `where(...)` from a later query is never attributed to this one.
    const rawWindow = source.slice(start, start + 600);
    const semi = rawWindow.indexOf(';');
    const window = semi >= 0 ? rawWindow.slice(0, semi) : rawWindow;

    // Path segments = the string literals in the collection(...) args, before
    // any `where(`. Dynamic segments (variables) are omitted, matching the way
    // the rules key drops `{wildcards}` — so literal sequences align.
    const firstWhere = window.indexOf('where(');
    const args = firstWhere >= 0 ? window.slice(0, firstWhere) : window;
    const segments = [];
    const segRe = /'([^']+)'/g;
    let sm;
    while ((sm = segRe.exec(args))) segments.push(sm[1]);

    /** @type {Set<string>} */
    const whereFields = new Set();
    const whereRe = /where\(\s*'([^']+)'\s*,/g;
    let wm;
    while ((wm = whereRe.exec(window))) whereFields.add(wm[1]);

    // A read (listener or one-shot get) near the collection, not a write.
    const context = source.slice(Math.max(0, m.index - 120), start + 60);
    const read = /\b(onSnapshot|getDocs)\s*\(/.test(context);

    queries.push({
      pathKey: segments.join('/'),
      whereFields,
      read,
      line: source.slice(0, m.index).split('\n').length,
    });
  }
  return queries;
}

/**
 * Find the rule governing a query path: the longest rule key that is a segment
 * prefix of (or equal to) the query key.
 * @param {RulesScope} scope
 * @param {string} queryKey
 * @returns {FirestoreScopeRule | null}
 */
export function matchScopeRule(scope, queryKey) {
  /** @type {{ key: string, rule: FirestoreScopeRule } | null} */
  let best = null;
  for (const [key, rule] of scope) {
    if (queryKey === key || queryKey.startsWith(`${key}/`)) {
      if (!best || key.length > best.key.length) best = { key, rule };
    }
  }
  return best ? best.rule : null;
}
