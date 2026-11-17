// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Shared secret-value classification.
 *
 * Decides whether a flagged secret line should be SKIPPED (not reported)
 * because its value is public-by-design or intentionally inert:
 *
 *   - Firebase web `apiKey` (AIzaSy…) used with the Firebase Auth REST API.
 *   - reCAPTCHA / App Check SITE keys (6L…) labelled as such in source.
 *   - Placeholder secrets (`sk_test_placeholder`, `changeme`, …).
 *   - Character-set / alphabet constants (Crockford Base32, Base64, …).
 *
 * Used by gitleaks (the scoring secret engine) and trivy (its advisory
 * confirm), so the two agree on what is and isn't a real secret. The secret
 * VALUE is inspected only for a boolean decision and never copied out.
 */
import { readFileSync } from 'node:fs';

/**
 * Read one 1-based line from a file. Returns '' on any error.
 * @param {string} file — absolute path
 * @param {number} lineNumber — 1-based
 * @returns {string}
 */
export function readLine(file, lineNumber) {
  try {
    const lines = readFileSync(file, 'utf8').split(/\r?\n/);
    return lines[Math.max(0, lineNumber - 1)] ?? '';
  } catch {
    return '';
  }
}

/**
 * Whether the file drives the Firebase Auth REST API
 * (`identitytoolkit.googleapis.com`), whose `key` query parameter is the public
 * Firebase web apiKey by construction. Pilot/CLI scripts that exercise Identity
 * Toolkit directly carry the same key the browser bundle ships.
 * @param {string} file — absolute path
 * @returns {boolean}
 */
function fileUsesFirebaseAuthRest(file) {
  try {
    return readFileSync(file, 'utf8').includes('identitytoolkit.googleapis.com');
  } catch {
    return false;
  }
}

/**
 * Classify a leak by the VALUE on its flagged line as public-by-design. The
 * line text is discarded after the check — nothing sensitive is retained.
 * @param {string} lineText — the flagged source line (never stored)
 * @param {string} file — absolute path (for the Firebase Auth REST usage test)
 * @returns {boolean}
 */
export function isPublicByDesignValue(lineText, file) {
  // Firebase web apiKey (AIzaSy…) used with the Firebase Auth REST endpoint —
  // the `key` query param IS the public browser key, never a server credential.
  if (/AIzaSy[A-Za-z0-9_-]{20,}/.test(lineText) && fileUsesFirebaseAuthRest(file)) {
    return true;
  }
  // reCAPTCHA / App Check SITE key (6L…) labelled as such in source. The secret
  // counterpart is server-only and is never labelled "site".
  if (/6L[A-Za-z0-9_-]{30,}/.test(lineText) && /site[_ -]?key|app[_ -]?check/i.test(lineText)) {
    return true;
  }
  return false;
}

/**
 * Whether a flagged line carries an intentionally-inert value rather than a
 * real secret: a placeholder (`sk_test_placeholder`, `changeme`, …) or a
 * character-set / alphabet constant (Crockford Base32, Base64, …). Gitleaks'
 * generic-api-key rule fires on both, but neither is a defect.
 * @param {string} lineText — the flagged source line (never stored)
 * @returns {boolean}
 */
export function isInertSecret(lineText) {
  // Placeholder secret: the VALUE is a literal placeholder marker (no word
  // boundaries — `sk_test_placeholder` has an underscore before the marker).
  if (/placeholder|changeme|your[-_ ]?(key|secret|token)/i.test(lineText)) {
    return true;
  }
  // Alphabet constant: a named character set is not a credential.
  if (
    /alphabet|base32|base64|charset|char[-_ ]?set|alphanum/i.test(lineText) &&
    /['"`][A-Za-z0-9+/_-]{20,}['"`]/.test(lineText)
  ) {
    return true;
  }
  return false;
}

/**
 * Should this flagged secret line be skipped outright (public-by-design or
 * inert), rather than reported as a finding?
 * @param {string} lineText — the flagged source line (never stored)
 * @param {string} file — absolute path
 * @returns {boolean}
 */
export function shouldSkipSecret(lineText, file) {
  return isPublicByDesignValue(lineText, file) || isInertSecret(lineText);
}
