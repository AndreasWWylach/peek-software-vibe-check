#!/usr/bin/env node
// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview CLI entry point for the vibe-check engine.
 *
 * Usage:
 *   vibe-check run --config peek-config.json [--out DIR] [--quiet]
 *   vibe-check --version
 *   vibe-check --help
 */
import { resolve } from 'node:path';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { run } from '../src/run.mjs';
import { probeUrl } from '../src/probe.mjs';
import { doctor, runOnboarding } from '../src/onboarding.mjs';
import { renderFixPrompts } from '../src/fix-prompts.mjs';
import { ENGINE_NAME, ENGINE_VERSION } from '../src/version.mjs';

const HELP = `vibe-check — open-source, local deep-scan engine for peek.software

Usage:
  vibe-check run --config <path> [--out <dir>] [--quiet] [--no-fix-prompts]
  vibe-check fix-prompts --report <peek-report.json> [--out <dir>]
  vibe-check probe <url> [--json] [--out <dir>]
  vibe-check doctor [--no-color]
  vibe-check setup [--dry-run] [--yes] [--skip <tool>...] [--no-color]
  vibe-check --version
  vibe-check --help

Commands:
  run          Run a scan against a peek-config.json. Writes AUDIT-REPORT.md,
               peek-report.json and FIX-PROMPTS.md (see --no-fix-prompts).
  fix-prompts  Re-generate FIX-PROMPTS.md from an existing peek-report.json —
               no re-scan, works offline.
  probe        OPT-IN live check of a deployed URL you own (read-only, bounded).
  doctor       Read-only onboarding check — what's installed, missing, or outdated.
  setup        Interactive onboarding — install the missing tools, step by step.

Options:
  --config <path>    Path to peek-config.json (required for run).
  --out <dir>        Directory for the reports (default: current directory).
  --json             Machine-readable output (probe only).
  --quiet            Suppress progress output (run only).
  --no-fix-prompts   Skip writing FIX-PROMPTS.md (run only).
  --report <path>    Path to peek-report.json (required for fix-prompts).
  --dry-run          Print every planned install step without running anything.
  --yes              Accept all install steps without prompting.
  --skip <tool>      Skip a tool by id (repeatable): node semgrep osv-scanner madge scc gitleaks eslint.
  --no-color         Plain output (no ANSI colors).
  -v, --version      Print the engine version.
  -h, --help         Print this help.`;

/** @typedef {{ command: 'help' } | { command: 'version' } | { command: 'run'; config: string; out: string | null; quiet: boolean; fixPrompts: boolean } | { command: 'fix-prompts'; report: string; out: string | null } | { command: 'probe'; target: string; json: boolean; out: string | null } | { command: 'doctor'; color: boolean } | { command: 'setup'; yes: boolean; dryRun: boolean; skip: string[]; color: boolean }} ParsedArgs */

/**
 * Parse CLI arguments (minimal, dependency-free).
 * @param {string[]} argv — `process.argv.slice(2)`.
 * @returns {ParsedArgs}
 */
function parseArgs(argv) {
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    return { command: 'help' };
  }
  if (argv.includes('--version') || argv.includes('-v')) {
    return { command: 'version' };
  }

  const command = argv[0];

  if (command === 'doctor') {
    return { command: 'doctor', color: !argv.includes('--no-color') };
  }

  if (command === 'setup') {
    let yes = false;
    let dryRun = false;
    /** @type {string[]} */
    const skip = [];
    let color = true;
    for (let i = 1; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '--yes') yes = true;
      else if (arg === '--dry-run') dryRun = true;
      else if (arg === '--no-color') color = false;
      else if (arg === '--skip') {
        const value = argv[++i];
        if (!value) throw new Error('--skip requires a tool id.');
        skip.push(...value.split(','));
      } else if (arg === '--check') {
        return { command: 'doctor', color };
      } else {
        throw new Error(`Unknown flag "${arg}". Run "vibe-check --help".`);
      }
    }
    return { command: 'setup', yes, dryRun, skip, color };
  }

  if (command === 'run') {
    /** @type {string | null} */
    let config = null;
    /** @type {string | null} */
    let out = null;
    let quiet = false;
    let fixPrompts = true;
    for (let i = 1; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '--config') config = argv[++i];
      else if (arg === '--out') out = argv[++i];
      else if (arg === '--quiet') quiet = true;
      else if (arg === '--no-fix-prompts') fixPrompts = false;
      else throw new Error(`Unknown flag "${arg}". Run "vibe-check --help".`);
    }
    if (!config) throw new Error('Missing required --config <path>. Run "vibe-check --help".');
    return { command: 'run', config, out, quiet, fixPrompts };
  }

  if (command === 'fix-prompts') {
    /** @type {string | null} */
    let report = null;
    /** @type {string | null} */
    let out = null;
    for (let i = 1; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '--report') report = argv[++i];
      else if (arg === '--out') out = argv[++i];
      else throw new Error(`Unknown flag "${arg}". Run "vibe-check --help".`);
    }
    if (!report) throw new Error('Missing required --report <peek-report.json>. Run "vibe-check --help".');
    return { command: 'fix-prompts', report, out };
  }

  if (command === 'probe') {
    const target = argv[1];
    if (!target || target.startsWith('--')) {
      throw new Error('Missing required <url>. Run "vibe-check --help".');
    }
    /** @type {string | null} */
    let out = null;
    let json = false;
    for (let i = 2; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '--out') out = argv[++i];
      else if (arg === '--json') json = true;
      else throw new Error(`Unknown flag "${arg}". Run "vibe-check --help".`);
    }
    return { command: 'probe', target, json, out };
  }

  throw new Error(`Unknown command "${command}". Run "vibe-check --help".`);
}

/**
 * CLI entry point.
 * @returns {Promise<void>}
 */
async function main() {
  const parsed = parseArgs(process.argv.slice(2));

  if (parsed.command === 'help') {
    console.log(HELP);
    return;
  }
  if (parsed.command === 'version') {
    console.log(`${ENGINE_NAME} ${ENGINE_VERSION}`);
    return;
  }
  if (parsed.command === 'doctor') {
    doctor({ color: parsed.color });
    return;
  }
  if (parsed.command === 'setup') {
    await runOnboarding({ yes: parsed.yes, dryRun: parsed.dryRun, skip: parsed.skip, color: parsed.color });
    return;
  }

  if (parsed.command === 'probe') {
    const report = await probeUrl(parsed.target, {
      log: parsed.json ? /** @param {string} _line */ ((_line) => {}) : (line) => console.log(line),
    });
    if (parsed.out) {
      await mkdir(parsed.out, { recursive: true });
      await writeFile(resolve(parsed.out, 'probe-report.json'), JSON.stringify(report, null, 2) + '\n', 'utf8');
      console.log(`wrote probe-report.json (${report.summary.pass} pass, ${report.summary.fail} fail, ${report.summary.warn} warn)`);
    }
    if (parsed.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`summary: ${report.summary.pass} pass · ${report.summary.fail} fail · ${report.summary.warn} warn`);
    }
    if (report.summary.fail > 0) process.exitCode = 1;
    return;
  }

  if (parsed.command === 'fix-prompts') {
    const reportPath = resolve(process.cwd(), parsed.report);
    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    const { markdown, count } = renderFixPrompts(report);
    const outDir = parsed.out ? resolve(process.cwd(), parsed.out) : resolve(reportPath, '..');
    await mkdir(outDir, { recursive: true });
    await writeFile(resolve(outDir, 'FIX-PROMPTS.md'), markdown, 'utf8');
    console.log(`wrote FIX-PROMPTS.md (${count} prompt(s))`);
    return;
  }

  const repoRoot = process.cwd();
  const outDir = parsed.out ? resolve(repoRoot, parsed.out) : repoRoot;
  const configPath = resolve(repoRoot, parsed.config);
  await run(configPath, { repoRoot, outDir, quiet: parsed.quiet, fixPrompts: parsed.fixPrompts });
}

main().catch((err) => {
  console.error(`vibe-check: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
