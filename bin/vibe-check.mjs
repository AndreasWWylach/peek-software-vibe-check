#!/usr/bin/env node
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
import { run } from '../src/run.mjs';
import { doctor, runOnboarding } from '../src/onboarding.mjs';
import { ENGINE_NAME, ENGINE_VERSION } from '../src/version.mjs';

const HELP = `vibe-check — open-source, local deep-scan engine for peek.software

Usage:
  vibe-check run --config <path> [--out <dir>] [--quiet]
  vibe-check doctor [--no-color]
  vibe-check setup [--dry-run] [--yes] [--skip <tool>...] [--no-color]
  vibe-check --version
  vibe-check --help

Commands:
  run          Run a scan against a peek-config.json.
  doctor       Read-only onboarding check — what's installed, missing, or outdated.
  setup        Interactive onboarding — install the missing tools, step by step.

Options:
  --config <path>   Path to peek-config.json (required for run).
  --out <dir>       Directory for the reports (default: current directory).
  --quiet           Suppress progress output (run only).
  --dry-run         Print every planned install step without running anything.
  --yes             Accept all install steps without prompting.
  --skip <tool>     Skip a tool by id (repeatable): node semgrep osv-scanner madge scc gitleaks eslint.
  --no-color        Plain output (no ANSI colors).
  -v, --version     Print the engine version.
  -h, --help        Print this help.`;

/** @typedef {{ command: 'help' } | { command: 'version' } | { command: 'run'; config: string; out: string | null; quiet: boolean } | { command: 'doctor'; color: boolean } | { command: 'setup'; yes: boolean; dryRun: boolean; skip: string[]; color: boolean }} ParsedArgs */

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
    for (let i = 1; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '--config') config = argv[++i];
      else if (arg === '--out') out = argv[++i];
      else if (arg === '--quiet') quiet = true;
      else throw new Error(`Unknown flag "${arg}". Run "vibe-check --help".`);
    }
    if (!config) throw new Error('Missing required --config <path>. Run "vibe-check --help".');
    return { command: 'run', config, out, quiet };
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

  const repoRoot = process.cwd();
  const outDir = parsed.out ? resolve(repoRoot, parsed.out) : repoRoot;
  const configPath = resolve(repoRoot, parsed.config);
  await run(configPath, { repoRoot, outDir, quiet: parsed.quiet });
}

main().catch((err) => {
  console.error(`vibe-check: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
