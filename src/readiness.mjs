// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Go-live readiness verdict.
 *
 * The headline risk score answers "how defective is your code?" — it does NOT
 * answer "can I ship this?". This module answers the latter from signals the
 * engine already has (dependency CVE severity, CI pipeline maturity, App Check
 * enforcement, disabled checks), so the report leads with an honest go/no-go
 * call instead of burying those signals in appendices.
 *
 * Pure and deterministic — every signal is passed in, nothing is read here.
 */

/** @typedef {import('./types.mjs').Readiness} Readiness */

/**
 * Compute the go-live readiness verdict.
 * @param {{
 *   deps: { critical: number; high: number };
 *   ci: { noPipeline: boolean; noTests: boolean; noCoverage: boolean };
 *   appCheckOff: boolean | null; // true = Firebase App Check off, false = on, null = n/a
 *   disabledCount: number;
 * }} input
 * @returns {Readiness}
 */
export function computeReadiness({ deps, ci, appCheckOff, disabledCount }) {
  /** @type {string[]} */
  const conditions = [];

  // Dependency CVEs are the strongest, most objective launch blocker.
  if (deps.critical > 0) {
    conditions.push(`${deps.critical} critical dependency CVE(s) — patch before launch.`);
  }
  if (deps.high > 0) {
    conditions.push(`${deps.high} high dependency CVE(s) — upgrade before launch.`);
  }

  // CI maturity: a pipeline that runs tests and enforces coverage catches
  // regressions before they reach production.
  if (ci.noPipeline) {
    conditions.push('No CI pipeline — tests and checks are not enforced on every change.');
  } else if (ci.noTests) {
    conditions.push('CI runs no tests.');
  } else if (ci.noCoverage) {
    conditions.push('CI runs tests without a coverage gate.');
  }

  // Firebase App Check verifies callers are the real client (not a forged SDK).
  if (appCheckOff === true) {
    conditions.push('App Check enforcement is off — callables do not verify the client.');
  }

  // Disabled checks mean the score is incomplete (see the Disabled Checks section).
  if (disabledCount > 0) {
    conditions.push(`${disabledCount} check(s) disabled — re-run with them enabled to complete the score.`);
  }

  // Critical CVEs are launch-blocking; anything else is "ship with conditions";
  // a clean bill produces "ready to go live".
  const status = deps.critical > 0 ? 'no-go' : conditions.length > 0 ? 'conditional' : 'go';
  return { status, conditions };
}
