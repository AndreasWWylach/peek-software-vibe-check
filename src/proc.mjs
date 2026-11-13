// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

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

/**
 * Run an external command and return its stdout + exit status WITHOUT throwing
 * on a non-zero exit (some tools exit non-zero to signal "findings found").
 * @param {string} command — binary name.
 * @param {string[]} args — arguments.
 * @param {{ cwd?: string }} [options]
 * @returns {{ status: number; stdout: string }}
 * @throws {Error} only when the binary cannot be spawned at all (e.g. ENOENT).
 */
export function runCommandCapture(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
  if (result.error) {
    throw new Error(`\`${command}\` could not be run: ${result.error.message}`);
  }
  return { status: result.status ?? 0, stdout: String(result.stdout ?? '') };
}
