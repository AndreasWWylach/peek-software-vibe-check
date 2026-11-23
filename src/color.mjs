// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Minimal terminal-color helper for the CLI's own output.
 *
 * Deliberately tiny: the run output colors only a few lines (provider headers,
 * finding counts, the risk line, the final summary). Colors are disabled when
 * stdout is not a terminal (piped/CI) or when `NO_COLOR` is set; `FORCE_COLOR=1`
 * forces them for captures and screenshots.
 */
const colorEnabled = Boolean(process.env.FORCE_COLOR) || (Boolean(process.stdout?.isTTY) && !('NO_COLOR' in process.env));

/**
 * Wrap text in an ANSI SGR color sequence when colors are enabled.
 * @param {string} code - SGR code, e.g. `36` (cyan) or `1;33` (bold amber).
 * @param {string} text
 * @returns {string}
 */
export function paint(code, text) {
  return colorEnabled ? `\x1b[${code}m${text}\x1b[0m` : text;
}
