// @ts-check
/**
 * @fileoverview Thin, dependency-free wrappers around `node:child_process` for
 * invoking external provider binaries (semgrep, osv-scanner, …).
 */
import { execFileSync, spawnSync } from 'node:child_process';

/**
 * Is `command` available on PATH? (non-throwing, fast `--version` probe)
 * @param {string} command — the binary name, e.g. "semgrep".
 * @returns {boolean} true when the binary exists and exits 0 for `--version`.
 */
export function commandAvailable(command) {
  const result = spawnSync(command, ['--version'], { stdio: 'ignore' });
  return !result.error && result.status === 0;
}

/**
 * Run an external command and return its stdout.
 * @param {string} command — binary name.
 * @param {string[]} args — arguments.
 * @param {{ cwd?: string }} [options]
 * @returns {string} captured stdout.
 * @throws {Error} when the command exits non-zero (stderr included in the message).
 */
export function runCommand(command, args, options = {}) {
  try {
    const output = execFileSync(command, args, {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      ...options,
    });
    return String(output);
  } catch (err) {
    const stderr =
      err && typeof err === 'object' && 'stderr' in err
        ? String(/** @type {{ stderr?: unknown }} */ (err).stderr)
        : '';
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`\`${command} ${args.join(' ')}\` failed: ${message}${stderr ? `\n${stderr}` : ''}`);
  }
}
