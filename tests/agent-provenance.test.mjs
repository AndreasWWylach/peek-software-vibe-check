// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Tests for agent-provenance detection — official AI-tool markers
 * (config files + git commit trailers) and user-named agent-log patterns.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { detectAgentProvenance } from '../src/agent-provenance.mjs';
import { commandAvailable } from '../src/proc.mjs';

/** @returns {string} a fresh temp dir. */
const tempDir = () => mkdtempSync(join(tmpdir(), 'vibe-check-provenance-'));

test('detects official instruction/config markers', () => {
  const dir = tempDir();
  try {
    mkdirSync(join(dir, '.github'), { recursive: true });
    writeFileSync(join(dir, 'CLAUDE.md'), '# Claude Code instructions\n');
    writeFileSync(join(dir, 'AGENTS.md'), '# agents\n');
    writeFileSync(join(dir, '.cursorrules'), 'some rules\n');
    writeFileSync(join(dir, '.github', 'copilot-instructions.md'), '');
    const result = detectAgentProvenance({ repoRoot: dir, targets: [dir], patterns: [] });
    assert.ok(result.signals.includes('Claude Code (CLAUDE.md)'));
    assert.ok(result.signals.includes('Agent instructions (AGENTS.md)'));
    assert.ok(result.signals.includes('Cursor (.cursorrules)'));
    assert.ok(result.signals.includes('GitHub Copilot (.github/copilot-instructions.md)'));
    assert.deepEqual(result.agentLogFiles, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('finds user-named agent-log files by glob pattern', () => {
  const dir = tempDir();
  try {
    mkdirSync(join(dir, 'docs'), { recursive: true });
    mkdirSync(join(dir, 'src'), { recursive: true });
    writeFileSync(join(dir, 'docs', 'BUILD_RUN_2026-11-16.md'), 'run');
    writeFileSync(join(dir, 'docs', 'UI_REVIEW_2026-11-17.md'), 'review');
    writeFileSync(join(dir, 'src', 'app.ts'), 'export {}');
    const result = detectAgentProvenance({
      repoRoot: dir,
      targets: [join(dir, 'src')],
      patterns: ['BUILD_RUN_*.md', 'UI_REVIEW_*.md'],
    });
    assert.deepEqual(result.agentLogFiles, ['docs/BUILD_RUN_2026-11-16.md', 'docs/UI_REVIEW_2026-11-17.md']);
    assert.deepEqual(result.signals, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('reports nothing for a plain repo', () => {
  const dir = tempDir();
  try {
    mkdirSync(join(dir, 'src'), { recursive: true });
    writeFileSync(join(dir, 'src', 'app.ts'), 'export {}');
    const result = detectAgentProvenance({ repoRoot: dir, targets: [join(dir, 'src')], patterns: [] });
    assert.deepEqual(result.signals, []);
    assert.deepEqual(result.agentLogFiles, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('detects Claude Code commit trailers in git history', { skip: !commandAvailable('git') }, () => {
  const dir = tempDir();
  try {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    const author = ['-c', 'user.email=test@example.com', '-c', 'user.name=Test'];
    writeFileSync(join(dir, 'file.txt'), 'one');
    execFileSync('git', ['add', 'file.txt'], { cwd: dir });
    execFileSync('git', [...author, 'commit', '-q', '-m', 'initial'], { cwd: dir });
    writeFileSync(join(dir, 'file.txt'), 'two');
    execFileSync('git', ['add', 'file.txt'], { cwd: dir });
    execFileSync(
      'git',
      [...author, 'commit', '-q', '-m', 'work', '-m', 'Co-Authored-By: Claude <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_x'],
      { cwd: dir },
    );

    const result = detectAgentProvenance({ repoRoot: dir, targets: [dir], patterns: [] });
    assert.ok(result.signals.includes('Claude Code (Co-Authored-By commit trailer)'), JSON.stringify(result.signals));
    assert.ok(result.signals.includes('Claude Code (Claude-Session commit trailer)'), JSON.stringify(result.signals));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
