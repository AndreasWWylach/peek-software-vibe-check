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
 * @property {Set<string>} required - union of all scope fields across branches (legacy single-branch view).
 * @property {string[][]} branches - alternative scope-field sets; a compliant query satisfies any one branch.
 * @property {boolean} requiresAuth - every read rule references `request.auth` / `uid()`.
 * @property {boolean} recursive - the match path ends in `{...=**}` and governs subpaths.
 * @property {boolean} leadingRecursive - the first path segment is `{...=**}` (governs paths ABOVE its key).
 */

/** @typedef {Map<string, FirestoreScopeRule>} RulesScope */
/** @typedef {{ path: string, readLines: string[] }} MatchBlock */
/** @typedef {Map<string, string>} HelperMap */

/**
 * @typedef {{ kind: 'match' | 'function', path: string, name: string, openDepth: number, lines: string[], openAllow: boolean }} BlockEntry
 */

const MAX_HELPER_DEPTH = 5;
const MAX_BRANCHES = 8;

/**
 * Parse `firestore.rules` into a path -> scope map, resolving helper functions.
 *
 * @param {string} text - full rules file text.
 * @returns {RulesScope} key = literal path segments joined by `/` (wildcards dropped).
 */
export function parseRulesScope(text) {
  const { matches, helpers } = parseRuleBlocks(text);
  /** @type {Map<string, FirestoreScopeRule>} */
  const scope = new Map();
  for (const block of matches) {
    const collection = blockCollection(block.path);
    const rule = toScopeRule(block.readLines, helpers, collection);
    if (rule) {
      const pathSegments = segmentsAfterDocuments(block.path);
      rule.recursive = pathSegments.some((segment) => segment.includes('=**'));
      rule.leadingRecursive = (pathSegments[0] ?? '').includes('=**');
      scope.set(pathKey(block.path), rule);
    }
  }
  return scope;
}

/**
 * Split the rules text into match blocks + helper function bodies.
 * Handles nesting (`match` blocks inside `match` blocks, `function` inside
 * `match`) by brace-depth tracking.
 * @param {string} text
 * @returns {{ matches: MatchBlock[], helpers: HelperMap }}
 */
export function parseRuleBlocks(text) {
  /** @type {MatchBlock[]} */
  const matches = [];
  /** @type {HelperMap} */
  const helpers = new Map();
  /** @type {BlockEntry[]} */
  const stack = [];
  let depth = 0;

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    const match = /^match\s+(\/\S+)\s*\{/.exec(trimmed);
    const fn = /^function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{/.exec(trimmed);
    if (match) {
      const relPath = match[1].trim();
      const parent = stack.length > 0 ? stack[stack.length - 1].path : '';
      const fullPath = (parent + '/' + relPath).replace(/\/{2,}/g, '/');
      const entry = /** @type {BlockEntry} */ ({
        kind: 'match',
        path: fullPath,
        name: '',
        openDepth: depth,
        lines: [],
        openAllow: false,
      });
      // A single-line match (`match /x/{id} { allow read: if ...; }`) - capture
      // the content after the opening brace when it is a read grant.
      const openIdx = line.indexOf('{');
      const rest = line.slice(openIdx + 1).replace(/\}\s*$/, '');
      if (rest.trim() && /^allow\s+(?:read|get|list)\b/.test(rest.trim())) entry.lines.push(rest.trim());
      stack.push(entry);
    } else if (fn) {
      const entry = /** @type {BlockEntry} */ ({
        kind: 'function',
        path: '',
        name: fn[1],
        openDepth: depth,
        lines: [],
        openAllow: false,
      });
      // Single-line function body - capture the content after the opening brace.
      const openIdx = line.indexOf('{');
      const rest = line.slice(openIdx + 1).replace(/\}\s*$/, '');
      if (rest.trim()) entry.lines.push(rest);
      stack.push(entry);
    } else if (stack.length > 0 && stack[stack.length - 1].kind === 'match') {
      const top = stack[stack.length - 1];
      if (/^allow\s+(?:read|get|list)\b/.test(trimmed)) {
        top.lines.push(trimmed);
        top.openAllow = !/;\s*$/.test(trimmed);
      } else if (top.openAllow) {
        // Multiline condition continuation (`|| ...` / `&& ...` lines).
        top.lines[top.lines.length - 1] += ` ${trimmed}`;
        top.openAllow = !/;\s*$/.test(top.lines[top.lines.length - 1]);
      }
    } else if (stack.length > 0 && stack[stack.length - 1].kind === 'function') {
      stack[stack.length - 1].lines.push(line);
    }

    depth += countChar(line, '{') - countChar(line, '}');

    while (stack.length > 0 && depth <= stack[stack.length - 1].openDepth) {
      const block = stack.pop();
      if (!block) continue;
      if (block.kind === 'match') {
        matches.push({ path: block.path, readLines: block.lines });
      } else {
        // Drop the closing-brace line captured in the body.
        const body = block.lines.filter((l) => !/^\s*\}\s*$/.test(l)).join('\n');
        helpers.set(block.name, body);
      }
    }
  }
  return { matches, helpers };
}

/**
 * Derive a scope rule from a match block's read lines - null when the block has
 * no reads, or has a public read (so the collection is not auth-gated).
 * @param {string[]} readLines
 * @param {HelperMap} helpers
 * @param {string} collection - the block's own collection name ('' when unknown).
 * @returns {FirestoreScopeRule | null}
 */
function toScopeRule(readLines, helpers, collection) {
  if (readLines.length === 0) return null;

  /** @type {Map<string, Set<string>[] | null>} */
  const branchMemo = new Map();
  /** @type {Map<string, Set<string> | null>} */
  const collectionMemo = new Map();
  /** @type {Map<string, boolean>} */
  const authMemo = new Map();

  /** @type {Set<string>[]} */
  const allBranches = [];
  let publicRead = false;

  for (const line of readLines) {
    const resolved = conditionBranches(line, helpers, collection, 0, branchMemo, collectionMemo, authMemo, true, true);
    if (resolved.public) {
      publicRead = true; // a non-auth alternative = public read = no blanket scope to enforce
      break;
    }
    if (!resolved.branches) return null; // too complex to resolve - skip rather than guess
    allBranches.push(...resolved.branches);
  }
  if (publicRead) return null;

  /** @type {Set<string>} */
  const required = new Set();
  /** @type {Set<string>[]} */
  const unique = [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const branch of allBranches) {
    const key = [...branch].sort().join('\u0000');
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(branch);
    for (const field of branch) required.add(field);
  }
  return {
    required,
    branches: unique.map((branch) => [...branch]),
    requiresAuth: true,
    recursive: false,
    leadingRecursive: false,
  };
}

/**
 * Resolve a full condition (`allow read: if ...`) into alternative field sets,
 * distributing `&&` over `||` at any nesting depth (DNF).
 * @param {string} condition
 * @param {HelperMap} helpers
 * @param {string} collection - the matched block's collection ('' when unknown).
 * @param {number} depth
 * @param {Map<string, Set<string>[] | null>} branchMemo
 * @param {Map<string, Set<string> | null>} collectionMemo
 * @param {Map<string, boolean>} authMemo
 * @param {boolean} checkPublic - only the top-level read line decides public-ness;
 * helper bodies are resolved for fields regardless of their own auth.
 * @param {boolean} paramFieldsAllowed - helper param/var `.get('f')` fields may
 * count. False once any helper in the chain reads a foreign collection.
 * @returns {{ branches: Set<string>[] | null, public: boolean }}
 */
function conditionBranches(condition, helpers, collection, depth, branchMemo, collectionMemo, authMemo, checkPublic, paramFieldsAllowed) {
  if (depth > MAX_HELPER_DEPTH) return { branches: null, public: false };
  /** @type {string[][]} */
  const dnf = [];
  toDnf(parseCondition(condition), dnf);
  /** @type {Set<string>[]} */
  const out = [];
  for (const branchTexts of dnf) {
    const joined = branchTexts.join(' ');
    if (checkPublic && !segmentAuth(joined, helpers, authMemo)) {
      return { branches: null, public: true };
    }
    // A branch that itself calls a foreign-collection helper disqualifies the
    // param fields of every helper it reaches (AND-propagates downward).
    const localAllowed = leafCollectionsAllowed(joined, helpers, collection, collectionMemo);
    const branches = conjunctionBranches(joined, helpers, collection, depth, branchMemo, collectionMemo, paramFieldsAllowed && localAllowed);
    if (!branches) return { branches: null, public: false };
    out.push(...branches);
    if (out.length > MAX_BRANCHES) return { branches: null, public: false };
  }
  // Deduplicate identical branch sets (empty helper chains repeat `∅`).
  /** @type {Set<string>[]} */
  const unique = [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const branch of out) {
    const key = [...branch].sort().join('\u0000');
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(branch);
    }
  }
  return { branches: unique, public: false };
}

/**
 * Do the helpers a condition calls read only the matched collection (or none)?
 * @param {string} text
 * @param {HelperMap} helpers
 * @param {string} collection
 * @param {Map<string, Set<string> | null>} collectionMemo
 * @returns {boolean}
 */
function leafCollectionsAllowed(text, helpers, collection, collectionMemo) {
  for (const name of calledHelpers(text, helpers)) {
    const collections = helperCollections(name, helpers, collectionMemo);
    if (collections === null) continue;
    for (const c of collections) {
      if (c !== collection) return false;
    }
  }
  return true;
}

/**
 * @typedef {{ type: 'or' | 'and', parts: CondNode[] }} LogicCondNode
 */
/**
 * @typedef {{ type: 'leaf', text: string }} LeafCondNode
 */
/**
 * @typedef {LogicCondNode | LeafCondNode} CondNode
 */

/**
 * Parse a condition into an OR/AND tree of leaf text fragments, respecting
 * parentheses and string literals. Leaves keep raw text (comparisons, calls).
 * @param {string} text
 * @returns {CondNode}
 */
function parseCondition(text) {
  let pos = 0;
  const skipWs = () => {
    while (pos < text.length && /\s/.test(text[pos])) pos += 1;
  };
  /**
   * @param {string} op
   * @returns {boolean}
   */
  const matchOp = (op) => {
    skipWs();
    if (text.startsWith(op, pos)) {
      pos += op.length;
      return true;
    }
    return false;
  };
  /** @returns {CondNode} */
  const parseOr = () => {
    /** @type {CondNode[]} */
    const parts = [parseAnd()];
    while (matchOp('||')) parts.push(parseAnd());
    return parts.length === 1 ? parts[0] : { type: 'or', parts };
  };
  /** @returns {CondNode} */
  const parseAnd = () => {
    /** @type {CondNode[]} */
    const parts = [parsePrimary()];
    while (matchOp('&&')) parts.push(parsePrimary());
    return parts.length === 1 ? parts[0] : { type: 'and', parts };
  };
  /** @returns {CondNode} */
  const parsePrimary = () => {
    skipWs();
    if (text[pos] === '(') {
      pos += 1;
      const inner = parseOr();
      skipWs();
      if (text[pos] === ')') pos += 1;
      return inner;
    }
    const start = pos;
    let parens = 0;
    let brackets = 0;
    let quote = null;
    while (pos < text.length) {
      const ch = text[pos];
      if (quote) {
        if (ch === quote) quote = null;
      } else if (ch === "'" || ch === '"') {
        quote = ch;
      } else if (ch === '$' && text[pos + 1] === '(') {
        // `$(database)` substitution group - skip it atomically (its `)` is
        // not a paren-depth change).
        let d = 1;
        pos += 2;
        while (pos < text.length && d > 0) {
          if (text[pos] === '(') d += 1;
          else if (text[pos] === ')') d -= 1;
          pos += 1;
        }
        continue;
      } else if (ch === '(') {
        parens += 1;
      } else if (ch === ')') {
        if (parens === 0) break;
        parens -= 1;
      } else if (ch === '[') {
        brackets += 1;
      } else if (ch === ']') {
        brackets -= 1;
      } else if ((ch === '|' && text[pos + 1] === '|') || (ch === '&' && text[pos + 1] === '&')) {
        if (parens === 0 && brackets === 0) break;
      }
      pos += 1;
    }
    return { type: 'leaf', text: text.slice(start, pos) };
  };
  return parseOr();
}

/**
 * Flatten an OR/AND tree into disjunctive normal form: an array of alternatives,
 * each an array of leaf texts joined by `&&`.
 * @param {CondNode} node
 * @param {string[][]} out
 */
function toDnf(node, out) {
  if (node.type === 'or') {
    for (const part of node.parts) toDnf(part, out);
  } else if (node.type === 'and') {
    /** @type {string[][]} */
    let lists = [[]];
    for (const part of node.parts) {
      /** @type {string[][]} */
      const sub = [];
      toDnf(part, sub);
      /** @type {string[][]} */
      const next = [];
      for (const list of lists) {
        for (const branch of sub) next.push([...list, ...branch]);
      }
      lists = next;
    }
    for (const list of lists) out.push(list);
  } else {
    out.push([/** @type {LeafCondNode} */ (node).text]);
  }
}

/**
 * Does a condition segment require auth, inline or via any called helper?
 * @param {string} segment
 * @param {HelperMap} helpers
 * @param {Map<string, boolean>} memo
 * @returns {boolean}
 */
function segmentAuth(segment, helpers, memo) {
  if (/\b(?:request\.auth|uid\s*\()/.test(segment)) return true;
  for (const name of calledHelpers(segment, helpers)) {
    if (helperAuth(name, helpers, memo)) return true;
  }
  return false;
}

/**
 * Transitive auth requirement of a helper body (recursive over helper calls).
 * @param {string} name
 * @param {HelperMap} helpers
 * @param {Map<string, boolean>} memo
 * @returns {boolean}
 */
function helperAuth(name, helpers, memo) {
  if (memo.has(name)) return /** @type {boolean} */ (memo.get(name));
  memo.set(name, false); // cycle guard
  const body = helpers.get(name);
  if (!body) return false;
  const auth = /\b(?:request\.auth|uid\s*\()/.test(body) ||
    calledHelpers(body, helpers).some((called) => helperAuth(called, helpers, memo));
  memo.set(name, auth);
  return auth;
}

/**
 * All collections a helper reads via `get(/databases/.../documents/<coll>/...)`,
 * transitively through the helpers it calls. Empty when it reads none (a helper
 * that only inspects the resource data passed to it).
 * @param {string} name
 * @param {HelperMap} helpers
 * @param {Map<string, Set<string> | null>} memo
 * @returns {Set<string> | null} null = could not resolve.
 */
function helperCollections(name, helpers, memo) {
  if (memo.has(name)) return /** @type {Set<string> | null} */ (memo.get(name));
  memo.set(name, new Set()); // cycle guard
  const body = helpers.get(name);
  if (body === undefined) return null;
  /** @type {Set<string>} */
  const collections = new Set();
  // `$(database)` substitution groups contain `)` - match them as units.
  const getRe = /get\(\s*\/databases\/(?:\$\([^)]*\)|[^)])*?\/documents\/([A-Za-z0-9_-]+)\//g;
  let m;
  while ((m = getRe.exec(body))) collections.add(m[1]);
  for (const called of calledHelpers(body, helpers)) {
    const sub = helperCollections(called, helpers, memo);
    if (sub === null) return null;
    for (const c of sub) collections.add(c);
  }
  memo.set(name, collections);
  return collections;
}

/**
 * Branches for a single `||`-free condition: inline fields cartesian-multiplied
 * with every called helper's alternatives.
 * @param {string} part
 * @param {HelperMap} helpers
 * @param {string} collection
 * @param {number} depth
 * @param {Map<string, Set<string>[] | null>} branchMemo
 * @param {Map<string, Set<string> | null>} collectionMemo
 * @param {boolean} paramFieldsAllowed
 * @returns {Set<string>[] | null}
 */
function conjunctionBranches(part, helpers, collection, depth, branchMemo, collectionMemo, paramFieldsAllowed) {
  /** @type {Set<string>[]} */
  let branches = [new Set(extractScopeFields(part, paramFieldsAllowed))];
  for (const name of calledHelpers(part, helpers)) {
    const helperResult = helperBranches(name, helpers, collection, depth + 1, branchMemo, collectionMemo, paramFieldsAllowed);
    if (!helperResult) return null;
    /** @type {Set<string>[]} */
    const next = [];
    for (const existing of branches) {
      for (const helperBranch of helperResult) {
        next.push(new Set([...existing, ...helperBranch]));
        if (next.length > MAX_BRANCHES) return null;
      }
    }
    branches = next;
  }
  return branches;
}

/**
 * The alternative required-field sets a helper contributes at a call site.
 * A helper that reads a DIFFERENT collection contributes no fields (auth only) -
 * the matched collection cannot satisfy a filter on another doc's fields.
 * @param {string} name
 * @param {HelperMap} helpers
 * @param {string} collection
 * @param {number} depth
 * @param {Map<string, Set<string>[] | null>} branchMemo
 * @param {Map<string, Set<string> | null>} collectionMemo
 * @param {boolean} paramFieldsAllowed
 * @returns {Set<string>[] | null}
 */
function helperBranches(name, helpers, collection, depth, branchMemo, collectionMemo, paramFieldsAllowed) {
  if (depth > MAX_HELPER_DEPTH) return null;
  const body = helpers.get(name);
  if (body === undefined) return null;
  const key = `${name}@${collection}@${paramFieldsAllowed ? 1 : 0}`;
  const cached = branchMemo.get(key);
  if (cached) return cached;
  branchMemo.set(key, null); // cycle guard
  /** @type {Map<string, boolean>} */
  const authMemo = new Map();
  const resolved = conditionBranches(body, helpers, collection, depth, branchMemo, collectionMemo, authMemo, false, paramFieldsAllowed);
  branchMemo.set(key, resolved.branches);
  return resolved.branches;
}

/**
 * The helper names a condition text calls (only names that are defined).
 * @param {string} text
 * @param {HelperMap} helpers
 * @returns {string[]}
 */
function calledHelpers(text, helpers) {
  /** @type {Set<string>} */
  const names = new Set();
  const callRe = /([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  let m;
  while ((m = callRe.exec(text))) {
    if (helpers.has(m[1])) names.add(m[1]);
  }
  return [...names];
}

/**
 * The collection name a match path governs: the last literal (non-`{...}`)
 * segment after `documents`. '' when every segment is a wildcard.
 * @param {string} path
 * @returns {string}
 */
function blockCollection(path) {
  const rest = segmentsAfterDocuments(path);
  for (let i = rest.length - 1; i >= 0; i -= 1) {
    if (!rest[i].startsWith('{')) return rest[i];
  }
  return '';
}

/**
 * The path segments after the `/databases/.../documents` root.
 * @param {string} path
 * @returns {string[]}
 */
function segmentsAfterDocuments(path) {
  const segments = path.split('/').filter(Boolean);
  const docsIdx = segments.findIndex((segment) => segment === 'documents');
  return docsIdx >= 0 ? segments.slice(docsIdx + 1) : segments;
}

/**
 * Extract `resource.data.*` field names a read rule compares to auth, plus
 * (optionally) `identifier.get('field')` fields - helper bodies use their
 * param (`p.get(...)`), which only counts when the data came from the matched
 * collection (`paramFieldsAllowed`).
 * @param {string} line
 * @param {boolean} [paramFieldsAllowed]
 * @returns {string[]}
 */
function extractScopeFields(line, paramFieldsAllowed = true) {
  /** @type {Set<string>} */
  const fields = new Set();
  const getRe = /resource\.data\.get\(\s*'([^']+)'/g;
  // Dot access to a field — skip method calls (`resource.data.size()`, …):
  // a field read is never followed by `(`.
  const dotRe = /resource\.data\.(?!\w+\()([A-Za-z_][A-Za-z0-9_]*)/g;
  let m;
  while ((m = getRe.exec(line))) fields.add(m[1]);
  while ((m = dotRe.exec(line))) fields.add(m[1]);
  if (paramFieldsAllowed) {
    // Any-identifier `.get('field')` — helper bodies use their param (`p.get(...)`),
    // and `resource.data.get('field')` matches here too (receiver `data`).
    const paramGetRe = /([A-Za-z_][A-Za-z0-9_]*)\s*\.get\(\s*'([^']+)'/g;
    while ((m = paramGetRe.exec(line))) fields.add(m[2]);
  }
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

    // Path segments = the string literals inside the collection(...) call,
    // bounded by its own closing paren (never the next statement's strings).
    // Template literals (`shoots/${id}/logs`) contribute their static parts.
    const args = balancedCallArgs(source, start);
    const segments = [];
    const segRe = /'([^']+)'/g;
    let sm;
    while ((sm = segRe.exec(args))) segments.push(sm[1]);
    const templateRe = /`([^`]*)`/g;
    let tm;
    while ((tm = templateRe.exec(args))) {
      const parts = tm[1].split(/\$\{[^}]*\}/);
      for (let pi = 0; pi < parts.length; pi += 1) {
        for (const seg of parts[pi].split('/')) {
          if (seg) segments.push(seg);
        }
        // A `${...}` interpolation is a dynamic segment - keep its depth so a
        // flattened `shoots/${id}/logs` (`shoots/*/logs`) never equals the
        // plain `shoots` match.
        if (pi < parts.length - 1) segments.push('*');
      }
    }

    // `where(...)` fields belong to the enclosing query() call - look after
    // the collection call closes, up to the next `;`.
    const windowEnd = args.length + start;
    const whereWindow = source.slice(windowEnd, windowEnd + 400);
    const semi = whereWindow.indexOf(';');
    const window = semi >= 0 ? whereWindow.slice(0, semi) : whereWindow;
    /** @type {Set<string>} */
    const whereFields = new Set();
    const whereRe = /where\(\s*'([^']+)'\s*,/g;
    let wm;
    while ((wm = whereRe.exec(window))) whereFields.add(wm[1]);

    // A read (listener or one-shot get) near the collection, not a write.
    const context = source.slice(Math.max(0, m.index - 120), windowEnd + 60);
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
 * The balanced parenthesized call arguments starting at `open`, honoring
 * string and template literals (`${...}` interpolations skipped atomically).
 * @param {string} source
 * @param {number} open - index just after the opening `(`.
 * @returns {string}
 */
function balancedCallArgs(source, open) {
  let depth = 1;
  let i = open;
  let quote = null;
  let inTemplate = false;
  while (i < source.length && depth > 0) {
    const ch = source[i];
    if (quote) {
      if (ch === quote && source[i - 1] !== '\\') quote = null;
    } else if (inTemplate) {
      if (ch === '`') {
        inTemplate = false;
      } else if (ch === '$' && source[i + 1] === '{') {
        let d = 1;
        i += 2;
        while (i < source.length && d > 0) {
          if (source[i] === '{') d += 1;
          else if (source[i] === '}') d -= 1;
          i += 1;
        }
        continue;
      }
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === '`') {
      inTemplate = true;
    } else if (ch === '(') {
      depth += 1;
    } else if (ch === ')') {
      depth -= 1;
    }
    i += 1;
  }
  return source.slice(open, Math.max(open, i - 1));
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
    if (!key) continue; // fully-wildcard paths never govern a query shape
    let matches = false;
    if (rule.leadingRecursive) {
      // `match /{path=**}/personnel/{id}` governs paths ABOVE its key too.
      matches = queryKey === key || queryKey.endsWith(`/${key}`);
    } else if (rule.recursive) {
      // `match /tenants/{t}/{d=**}` governs the whole subtree below its key.
      matches = queryKey === key || queryKey.startsWith(`${key}/`);
    } else {
      // A plain match governs ONLY its exact depth - `match /shoots/{shootId}`
      // does not govern `shoots/{shootId}/logs` (subcollections need their own
      // nested match, or a `{...=**}` wildcard).
      matches = queryKey === key;
    }
    if (matches && (!best || key.length > best.key.length)) best = { key, rule };
  }
  return best ? best.rule : null;
}
