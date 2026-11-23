// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Agent-provenance detection — official markers of AI-coding
 * tools, plus the custom agent-workflow log files the user asked to watch.
 *
 * Only OFFICIAL, tool-published signals are used here (config/instruction
 * files and git commit trailers). Project-specific workflow artifacts (e.g. a
 * team's `BUILD_RUN_*.md` convention) are NOT hard-coded — the user names
 * them via `ruleParams.agentLogPatterns` and they are reported verbatim, never
 * interpreted as a specific tool.
 */
import { existsSync, readdirSync } from 'node:fs';
import { join, relative, basename } from 'node:path';
import { IGNORED_DIRS } from './ignore.mjs';
import { runCommandCapture } from './proc.mjs';

/** Official instruction/config files that identify an AI-coding tool. */
const CONFIG_MARKERS = /** @type {Array<{ path: string; label: string }>} */ ([
  { path: 'CLAUDE.md', label: 'Claude Code (CLAUDE.md)' },
  { path: '.cursorrules', label: 'Cursor (.cursorrules)' },
  { path: '.cursor/rules', label: 'Cursor (.cursor/rules)' },
  { path: '.github/copilot-instructions.md', label: 'GitHub Copilot (.github/copilot-instructions.md)' },
  { path: '.aider.conf.yml', label: 'Aider (.aider.conf.yml)' },
  { path: 'AGENTS.md', label: 'Agent instructions (AGENTS.md)' },
]);

/** Claude Code's official commit trailers (the agent-specific provenance). */
const CLAUDE_COAUTHOR_RE = /^Co-Authored-By:\s*Claude\s*<noreply@anthropic\.com>/m;
const CLAUDE_SESSION_RE = /^Claude-Session:/m;

/**
 * How many recent commits to inspect for trailers. Bounded for determinism and
 * speed; an older commit's provenance is rarely the current working style.
 */
const GIT_LOG_LIMIT = 500;

/**
 * Detect official agent markers + user-named agent-log files.
 *
 * @param {{ repoRoot: string, targets: string[], patterns: string[] }} input
 * @returns {{ signals: string[], agentLogFiles: string[] }}
 */
export function detectAgentProvenance({ repoRoot, patterns }) {
  /** @type {Set<string>} */
  const signalSet = new Set();

  for (const marker of CONFIG_MARKERS) {
    if (existsSync(join(repoRoot, marker.path))) signalSet.add(marker.label);
  }

  // Git commit trailers — Claude Code's Co-Authored-By / Claude-Session lines.
  // Guarded: a non-git folder (or a missing `git`) simply contributes nothing.
  if (existsSync(join(repoRoot, '.git'))) {
    try {
      const { status, stdout } = runCommandCapture(
        'git',
        ['log', '--format=%B', '-n', String(GIT_LOG_LIMIT)],
        { cwd: repoRoot },
      );
      if (status === 0) {
        if (CLAUDE_COAUTHOR_RE.test(stdout)) signalSet.add('Claude Code (Co-Authored-By commit trailer)');
        if (CLAUDE_SESSION_RE.test(stdout)) signalSet.add('Claude Code (Claude-Session commit trailer)');
      }
    } catch {
      // git not installed / not a repo — no signal.
    }
  }

  // Custom agent-workflow log files the user asked to watch (never interpreted
  // as a specific tool — reported as the literal files they named).
  const agentLogFiles = patterns.length > 0 ? findMatchingFiles(repoRoot, patterns) : [];

  return {
    signals: [...signalSet].sort(),
    agentLogFiles,
  };
}

/**
 * Find repo-relative files whose basename or path matches one of the patterns.
 * Walks the whole repo (ignored dirs skipped), sorted for determinism.
 *
 * @param {string} repoRoot
 * @param {string[]} patterns — glob-like (`*`, `?`), e.g. `BUILD_RUN_*.md`.
 * @returns {string[]}
 */
function findMatchingFiles(repoRoot, patterns) {
  const matchers = patterns.map((pattern) => ({ re: globToRegExp(pattern) }));
  /** @type {string[]} */
  const all = [];
  collectFiles(repoRoot, repoRoot, all);

  /** @type {string[]} */
  const matches = [];
  for (const abs of all) {
    const rel = relative(repoRoot, abs).replace(/\\/g, '/');
    for (const { re } of matchers) {
      if (re.test(rel) || re.test(basename(rel))) {
        matches.push(rel);
        break;
      }
    }
  }
  return matches.sort();
}

/**
 * Recursively collect file paths under `dir` (absolute), skipping ignored dirs.
 * @param {string} dir
 * @param {string} repoRoot
 * @param {string[]} out
 */
function collectFiles(dir, repoRoot, out) {
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
      if (IGNORED_DIRS.has(entry.name)) continue;
      collectFiles(abs, repoRoot, out);
    } else {
      out.push(abs);
    }
  }
}

/**
 * Convert a `*`/`?` glob to an anchored RegExp (no `/` in `*` — a name wildcard).
 * @param {string} pattern
 * @returns {RegExp}
 */
function globToRegExp(pattern) {
  const body = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]');
  return new RegExp(`^${body}$`);
}
