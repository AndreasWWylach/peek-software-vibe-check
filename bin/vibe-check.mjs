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
import { ENGINE_NAME, ENGINE_VERSION } from '../src/version.mjs';

const HELP = `vibe-check — open-source, local deep-scan engine for peek.software

Usage:
  vibe-check run --config <path> [--out <dir>] [--quiet]
  vibe-check --version
  vibe-check --help

Commands:
  run          Run a scan against a peek-config.json.

Options:
  --config <path>   Path to peek-config.json (required for run).
  --out <dir>       Directory for the reports (default: current directory).
  --quiet           Suppress progress output.
  -v, --version     Print the engine version.
  -h, --help        Print this help.`;

/** @typedef {{ command: 'help' } | { command: 'version' } | { command: 'run'; config: string; out: string | null; quiet: boolean }} ParsedArgs */

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
  if (argv[0] !== 'run') {
    throw new Error(`Unknown command "${argv[0]}". Run "vibe-check --help".`);
  }

  /** @type {string | null} */
  let config = null;
  /** @type {string | null} */
  let out = null;
  let quiet = false;

  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--config') {
      config = argv[++i];
    } else if (arg === '--out') {
      out = argv[++i];
    } else if (arg === '--quiet') {
      quiet = true;
    } else {
      throw new Error(`Unknown flag "${arg}". Run "vibe-check --help".`);
    }
  }

  if (!config) {
    throw new Error('Missing required --config <path>. Run "vibe-check --help".');
  }

  return { command: 'run', config, out, quiet };
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

  const repoRoot = process.cwd();
  const outDir = parsed.out ? resolve(repoRoot, parsed.out) : repoRoot;
  const configPath = resolve(repoRoot, parsed.config);
  await run(configPath, { repoRoot, outDir, quiet: parsed.quiet });
}

main().catch((err) => {
  console.error(`vibe-check: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
