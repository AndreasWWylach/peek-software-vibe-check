// @ts-check
/**
 * @fileoverview Shared JSDoc type definitions for the vibe-check engine.
 *
 * These typedefs are the in-repo "contract" that mirrors the published JSON
 * Schemas in `schema/`. Keeping them in one module means every consumer
 * imports the same shapes (`import('./types.mjs').Finding`) instead of
 * re-declaring ad-hoc object literals. No runtime value is exported — this
 * module exists purely in type-space.
 */

/** The four diagnostic pillars (shared with the peek.software quiz). */
/** @typedef {'security' | 'runtime' | 'architecture' | 'qa'} Pillar */

/** Severity rating (shared with the peek.software teardown catalog). */
/** @typedef {'critical' | 'high' | 'medium' | 'low'} Severity */

/** Risk classification tier (shared with the quiz). */
/** @typedef {'green' | 'amber' | 'red'} Tier */

/** What kind of analysis produced a finding. */
/** @typedef {'teardown' | 'dependency' | 'hygiene'} FindingKind */

/**
 * Provenance of a finding — which provider + rule produced it.
 * @typedef {Object} FindingSource
 * @property {string} provider — provider id, e.g. "semgrep" or "osv".
 * @property {string | null} ruleId — the rule/check id within that provider.
 */

/**
 * Dependency (CVE) details, present only when `kind === 'dependency'`.
 * @typedef {Object} DependencyInfo
 * @property {string} package — package name.
 * @property {string | null} version — affected version (null when unknown).
 * @property {string | null} ecosystem — OSV ecosystem (npm/PyPI/Packagist/…).
 * @property {string[]} cveIds — associated CVE/OSV ids.
 */

/**
 * A single scan finding in the shared `peek-report.json` shape.
 * @typedef {Object} Finding
 * @property {string} id — stable, unique finding id.
 * @property {FindingKind} kind — teardown | dependency | hygiene.
 * @property {string} file — repo-relative path of the offending file.
 * @property {number | null} line — 1-based line number (null when N/A).
 * @property {number | null} column — 1-based column (null when N/A).
 * @property {Severity} severity
 * @property {Pillar} pillar
 * @property {string | null} teardownId — `TD-###` for teardown findings, else null.
 * @property {string} title — one-line description of the problem.
 * @property {string | null} message — expanded explanation (nullable).
 * @property {string | null} fixSummary — one-line fix (nullable).
 * @property {FindingSource} source — which provider + rule produced this.
 * @property {DependencyInfo | null} dependency — populated for dependency findings.
 */

/**
 * A per-pillar score cell in the report.
 * @typedef {Object} PillarScore
 * @property {Pillar} pillar
 * @property {string} label — human-readable pillar label.
 * @property {number} score — points contributed (capped at `max`).
 * @property {number} max — pillar maximum (from the quiz).
 */

/**
 * A provider that was skipped, with the reason.
 * @typedef {Object} SkipRecord
 * @property {string} id — provider id.
 * @property {'not-installed' | 'not-applicable' | 'error'} reason
 * @property {string | null} detail — human-readable explanation.
 */

/**
 * The validated scan configuration (`peek-config.json`).
 * @typedef {Object} ScanConfig
 * @property {number} version — config schema version.
 * @property {string} engine — minimum engine semver range.
 * @property {string[]} targets — paths to scan, relative to repo root.
 * @property {string[]} languages — detected languages (may be empty).
 * @property {string[]} enabledRules — facet-gated `TD-###` subset.
 * @property {Record<string, unknown>} ruleParams — reserved (v2).
 * @property {{ weights: Record<Pillar, number> }} scoring
 * @property {Record<string, unknown> | undefined} quiz — calibration data (v2).
 */

/**
 * Context handed to every provider while it runs.
 * @typedef {Object} RunContext
 * @property {string} repoRoot — absolute repo root.
 * @property {string[]} targets — resolved target paths (absolute).
 * @property {(line: string) => void} log — progress sink.
 */

/**
 * Provider contract — see `src/providers/registry.mjs`.
 * @typedef {Object} Provider
 * @property {string} id
 * @property {string} name — human-readable name.
 * @property {() => Promise<boolean> | boolean} available — is the binary installed?
 * @property {(config: ScanConfig) => boolean} applicable — does it fit this app?
 * @property {(config: ScanConfig, ctx: RunContext) => Promise<Finding[]>} run
 */

/**
 * A calibration moment — a quiz hotspot cross-checked against the scan.
 * @typedef {Object} CalibrationMoment
 * @property {string} questionId — quiz question id, e.g. "Q2.2".
 * @property {string | null} teardownId — the mapped teardown, or null when none.
 * @property {boolean} found — true when the scan found that teardown.
 */

/**
 * The self-report vs. scan calibration overlay (docs §3 level 2).
 * @typedef {Object} Calibration
 * @property {number} selfReport — quiz total score.
 * @property {number} scan — scan total score.
 * @property {Array<{ pillar: Pillar; selfReport: number; scan: number }>} pillars
 * @property {CalibrationMoment[]} moments
 */

/**
 * The complete audit report object (mirrors peek-report.schema.json).
 * @typedef {Object} Report
 * @property {number} schemaVersion
 * @property {{ name: string; version: string; commit: string | null }} engine
 * @property {string} generatedAt
 * @property {{ total: number; max: number; tier: Tier; riskPercentage: number }} riskScore
 * @property {PillarScore[]} pillars
 * @property {Finding[]} findings
 * @property {SkipRecord[]} skippedProviders
 * @property {Array<{ teardownId: string; title: string; guidance: string }>} notStaticallyVerifiable
 * @property {Calibration | undefined} calibration — self-report vs scan (when quiz data present).
 */

export {};
