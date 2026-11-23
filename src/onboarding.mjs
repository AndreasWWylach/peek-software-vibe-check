// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Onboarding — the guided installer for the vibe-check engine.
 *
 * One command, two personalities (docs §5.8):
 *   - `vibe-check doctor`        read-only prerequisite check.
 *   - `vibe-check setup`         interactive installer: y/n/skip per missing
 *                                tool, prints every command before running it,
 *                                idempotent, interruptible at any time.
 *
 * Transparency is a hard requirement: every tool declares WHAT it is, WHERE it
 * comes from, and the EXACT command (or download + checksum) that will run.
 * Nothing runs without being shown first.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { fileURLToPath } from 'node:url';
import { IGNORED_DIRS } from './ignore.mjs';
import { ENGINE_NAME, ENGINE_VERSION } from './version.mjs';

/** @typedef {import('./types.mjs').Severity} Severity */

/** Absolute path to the vendored PHP ruleset manifest. */
const VENDORED_MANIFEST = fileURLToPath(new URL('../rules/vendored/php/manifest.json', import.meta.url));

/** Absolute path to the vendored PHPStan extensions manifest. */
const VENDORED_PHPSTAN_MANIFEST = fileURLToPath(new URL('../rules/vendored/phpstan/manifest.json', import.meta.url));

/** Warn in `doctor` when the vendored assets are older than this (days). */
const RULESET_STALE_DAYS = 90;

/**
 * Read a vendored manifest and report its age + a caller-provided summary.
 * @param {string} manifestPath
 * @param {(manifest: Record<string, any>) => string} summarize
 * @returns {{ ageDays: number; summary: string } | null} null when absent/unparseable.
 */
function vendoredFreshness(manifestPath, summarize) {
  if (!existsSync(manifestPath)) return null;
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const ts = Date.parse(String(manifest.vendoredAt ?? ''));
    if (!Number.isFinite(ts)) return null;
    return {
      ageDays: Math.floor((Date.now() - ts) / 86400000),
      summary: summarize(manifest),
    };
  } catch {
    return null;
  }
}

/** @typedef {[number, number, number]} Semver */

/**
 * Install instructions for a tool.
 * @typedef {Object} InstallSpec
 * @property {'command' | 'download' | 'manual'} kind
 * @property {string} summary - one-line description of what will happen.
 * @property {string} source - official source URL (trust transparency).
 * @property {Record<string, string>} [commands] - per package-manager shell command.
 * @property {string} [url] - download URL (kind download).
 * @property {string} [sha256] - expected sha256 of the downloaded asset.
 * @property {'none' | 'tar.gz'} [archive] - none = raw binary, else tarball.
 * @property {string} [binary] - the binary name to install as.
 */

/**
 * A prerequisite tool the onboarding installs and the engine shells out to.
 * @typedef {Object} Tool
 * @property {string} id
 * @property {string} name
 * @property {string} role — what it does for the engine (one line).
 * @property {boolean} required — false = optional deep-mode tool.
 * @property {Semver} minVersion
 * @property {InstallSpec} install
 */

/**
 * The onboarding registry — one entry per engine prerequisite.
 * @type {Tool[]}
 */
export const TOOLS = [
  {
    id: 'node',
    name: 'Node.js',
    role: 'Runs the vibe-check engine itself.',
    required: true,
    minVersion: [22, 0, 0],
    install: {
      kind: 'manual',
      summary: 'Install Node.js ≥ 22 (needed before anything else runs)',
      source: 'https://nodejs.org',
      commands: {
        brew: 'brew install node@22',
        apt: 'curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs',
        dnf: 'sudo dnf module install -y nodejs:22',
        apk: 'sudo apk add nodejs',
        default: 'Download from https://nodejs.org (LTS ≥ 22)',
      },
    },
  },
  {
    id: 'semgrep',
    name: 'semgrep',
    role: 'Runs the custom teardown rules (core).',
    required: true,
    minVersion: [1, 0, 0],
    install: {
      kind: 'command',
      summary: 'Install semgrep via pipx (falls back to pip; bootstraps pip if missing)',
      source: 'https://semgrep.dev',
      commands: {
        default:
          'if command -v pipx >/dev/null 2>&1; then pipx install semgrep; ' +
          'elif command -v pip3 >/dev/null 2>&1; then pip3 install --user semgrep; ' +
          'elif python3 -m pip --version >/dev/null 2>&1; then python3 -m pip install --user semgrep; ' +
          'elif command -v python3 >/dev/null 2>&1; then ' +
          'echo "no pip/pipx found — bootstrapping pip via the official get-pip.py, then installing semgrep"; ' +
          'curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/vibe-check-get-pip.py && ' +
          'python3 /tmp/vibe-check-get-pip.py --user && ' +
          'python3 -m pip install --user semgrep; ' +
          'else echo "semgrep needs Python 3 with pip or pipx. Install python3 + python3-pip first (e.g. sudo apt-get install -y python3 python3-pip, or brew install semgrep), then re-run: vibe-check setup"; exit 1; fi',
      },
    },
  },
  {
    id: 'osv-scanner',
    name: 'osv-scanner',
    role: 'Scans lockfiles for dependency CVEs (core).',
    required: true,
    minVersion: [2, 0, 0],
    install: {
      kind: 'download',
      summary: 'Download osv-scanner v2.7.1 (linux amd64)',
      source: 'https://github.com/google/osv-scanner',
      url: 'https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64',
      sha256: 'fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8',
      archive: 'none',
      binary: 'osv-scanner',
    },
  },
  {
    id: 'madge',
    name: 'madge',
    role: 'Builds the dependency graph to find circular imports.',
    required: true,
    minVersion: [7, 0, 0],
    install: {
      kind: 'command',
      summary: 'Install madge via npm (global)',
      source: 'https://github.com/pahen/madge',
      commands: { default: 'npm install -g madge' },
    },
  },
  {
    id: 'scc',
    name: 'scc',
    role: 'Counts file sizes to flag monolithic files.',
    required: true,
    minVersion: [3, 0, 0],
    install: {
      kind: 'download',
      summary: 'Download scc v3.5.0 (linux amd64)',
      source: 'https://github.com/boyter/scc',
      url: 'https://github.com/boyter/scc/releases/download/v3.5.0/scc_Linux_x86_64.tar.gz',
      sha256: '6c31f4d0cf3b7a8c5ca910fa4e451949434798f6541ec5dea4b83f4973e13772',
      archive: 'tar.gz',
      binary: 'scc',
    },
  },
  {
    id: 'gitleaks',
    name: 'gitleaks',
    role: 'Scans for hardcoded secrets.',
    required: true,
    minVersion: [8, 0, 0],
    install: {
      kind: 'download',
      summary: 'Download gitleaks v8.30.1 (linux amd64)',
      source: 'https://github.com/gitleaks/gitleaks',
      url: 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz',
      sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
      archive: 'tar.gz',
      binary: 'gitleaks',
    },
  },
  {
    id: 'eslint',
    name: 'eslint',
    role: 'Language linter — QA-pillar hygiene findings.',
    required: true,
    minVersion: [9, 0, 0],
    install: {
      kind: 'command',
      summary: 'Install eslint v9 via npm (global)',
      source: 'https://eslint.org',
      commands: { default: 'npm install -g eslint@9' },
    },
  },
  {
    id: 'checkov',
    name: 'checkov',
    role: 'IaC misconfiguration + IAM policy scanning (optional).',
    required: false,
    minVersion: [2, 0, 0],
    install: {
      kind: 'command',
      summary: 'Install checkov via pipx (falls back to pip)',
      source: 'https://www.checkov.io',
      commands: {
        default:
          'if command -v pipx >/dev/null 2>&1; then pipx install checkov; ' +
          'elif command -v pip3 >/dev/null 2>&1; then pip3 install --user checkov; ' +
          'elif python3 -m pip --version >/dev/null 2>&1; then python3 -m pip install --user checkov; ' +
          'else echo "checkov needs Python 3 + pip or pipx — install semgrep first (its installer bootstraps pip), then re-run: vibe-check setup"; exit 1; fi',
      },
    },
  },
  {
    id: 'hadolint',
    name: 'hadolint',
    role: 'Dockerfile quality & hygiene lint (optional).',
    required: false,
    minVersion: [2, 0, 0],
    install: {
      kind: 'download',
      summary: 'Download hadolint v2.12.0 (linux amd64)',
      source: 'https://github.com/hadolint/hadolint',
      url: 'https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64',
      sha256: '56de6d5e5ec427e17b74fa48d51271c7fc0d61244bf5c90e828aab8362d55010',
      archive: 'none',
      binary: 'hadolint',
    },
  },
  {
    id: 'trivy',
    name: 'trivy',
    role: 'Filesystem vulnerability + secret scanning (optional).',
    required: false,
    minVersion: [0, 50, 0],
    install: {
      kind: 'download',
      summary: 'Download trivy v0.76.2 (linux amd64)',
      source: 'https://github.com/aquasecurity/trivy',
      url: 'https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz',
      sha256: 'bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf',
      archive: 'tar.gz',
      binary: 'trivy',
    },
  },
  {
    id: 'bandit',
    name: 'bandit',
    role: 'Python security SAST (optional).',
    required: false,
    minVersion: [1, 0, 0],
    install: {
      kind: 'command',
      summary: 'Install bandit via pipx (falls back to pip)',
      source: 'https://bandit.readthedocs.io',
      commands: {
        default:
          'if command -v pipx >/dev/null 2>&1; then pipx install bandit; ' +
          'elif command -v pip3 >/dev/null 2>&1; then pip3 install --user bandit; ' +
          'else echo "bandit needs pipx or pip — run the semgrep/checkov installer first"; exit 1; fi',
      },
    },
  },
  {
    id: 'gosec',
    name: 'gosec',
    role: 'Go security SAST (optional).',
    required: false,
    minVersion: [2, 20, 0],
    install: {
      kind: 'download',
      summary: 'Download gosec v2.30.0 (linux amd64)',
      source: 'https://github.com/securego/gosec',
      url: 'https://github.com/securego/gosec/releases/download/v2.30.0/gosec_2.30.0_linux_amd64.tar.gz',
      sha256: '3fcce2c4e802ff4169217874602a7df355e9a37bcb6ffaa34b08f3d5f336cdfb',
      archive: 'tar.gz',
      binary: 'gosec',
    },
  },
  {
    id: 'phpstan',
    name: 'phpstan',
    role: 'PHP static analysis (optional, needs PHP ≥ 8.1).',
    required: false,
    minVersion: [2, 0, 0],
    install: {
      kind: 'download',
      summary: 'Download phpstan v2.3.1 (PHAR)',
      source: 'https://phpstan.org',
      url: 'https://github.com/phpstan/phpstan/releases/download/2.3.1/phpstan.phar',
      sha256: '85157dba3d95d77ca603d2b7303aa78a538f9e3b56ccad07dd794c53aa96d1ae',
      binary: 'phpstan',
    },
  },
];

/**
 * Stack markers of the repo onboarding runs in (bounded walk).
 * @typedef {Object} StackNeeds
 * @property {boolean} anyStack — did any language/container marker show up?
 * @property {boolean} js — package.json present.
 * @property {boolean} python — requirements.txt / pyproject.toml / setup.py / Pipfile.
 * @property {boolean} php — composer.json.
 * @property {boolean} go — go.mod.
 * @property {boolean} docker — any Dockerfile*.
 * @property {boolean} iac — Dockerfile* / docker-compose* / *.tf.
 * @property {boolean} lockfile — any dependency lockfile.
 */

/**
 * Detect the repo's stack markers with a bounded walk (names only, no content).
 * Used to install only what THIS repo's stack needs. An empty/foreign
 * directory yields `anyStack: false` — then every tool stays a candidate.
 * @param {string} repoRoot
 * @returns {StackNeeds}
 */
export function detectStackNeeds(repoRoot) {
  /** @type {Set<string>} */
  const names = new Set();
  collectNames(repoRoot, names, 0);
  const js = names.has('package.json');
  const python = ['requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile'].some((n) => names.has(n));
  const php = names.has('composer.json');
  const go = names.has('go.mod');
  const docker = [...names].some((n) => n.startsWith('Dockerfile'));
  const iac = docker || [...names].some((n) => n.startsWith('docker-compose') || n.endsWith('.tf'));
  const lockfile = [
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'requirements.txt', 'poetry.lock', 'Pipfile.lock',
    'composer.lock', 'go.sum', 'Cargo.lock', 'Gemfile.lock',
  ].some((n) => names.has(n));
  return {
    anyStack: js || python || php || go || docker,
    js, python, php, go, docker, iac, lockfile,
  };
}

/**
 * Does THIS repo's stack actually need this tool? Engine-agnostic: a tool that
 * never matches this repo's stack is pure dead weight — skip installing it.
 * @param {string} toolId
 * @param {StackNeeds} stack
 * @returns {{ needed: boolean; reason: string }}
 */
export function toolNeed(toolId, stack) {
  switch (toolId) {
    case 'madge':
    case 'eslint':
      return { needed: stack.js, reason: 'no package.json — not a JS/TS repo' };
    case 'bandit':
      return { needed: stack.python, reason: 'no Python manifest detected' };
    case 'phpstan':
      return { needed: stack.php, reason: 'no composer.json — not a PHP repo' };
    case 'gosec':
      return { needed: stack.go, reason: 'no go.mod — not a Go repo' };
    case 'checkov':
      return { needed: stack.iac, reason: 'no Dockerfile/compose/Terraform detected' };
    case 'hadolint':
      return { needed: stack.docker, reason: 'no Dockerfile detected' };
    case 'trivy':
      return { needed: stack.lockfile || stack.docker, reason: 'no lockfile or Dockerfile detected' };
    default:
      // node, semgrep, osv-scanner, scc, gitleaks — the engine core, always.
      return { needed: true, reason: '' };
  }
}

/** Bounded name collection (cap 5000 files; skips ignored dirs + symlinks).
 * @param {string} dir
 * @param {Set<string>} names
 * @param {number} depth */
function collectNames(dir, names, depth) {
  if (names.size >= 5000 || depth > 6) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    names.add(entry.name);
    if (entry.isDirectory() && !IGNORED_DIRS.has(entry.name)) {
      collectNames(join(dir, entry.name), names, depth + 1);
    }
  }
}

/**
 * Extract the first `x.y.z` triple from a version string (or null).
 * @param {string} text
 * @returns {Semver | null}
 */
export function extractVersionTriple(text) {
  const match = String(text).match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/**
 * Compare two semver triples: negative when a < b, 0 when equal, positive when a > b.
 * @param {Semver} a
 * @param {Semver} b
 * @returns {number}
 */
export function compareSemver(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
  }
  return 0;
}

/**
 * Probe a tool's version via `--version` (best effort; null when missing).
 * @param {Tool} tool
 * @returns {Semver | null}
 */
export function lookupVersion(tool) {
  try {
    const out = execFileSync(tool.id, ['--version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return extractVersionTriple(out);
  } catch {
    return null;
  }
}

/** @typedef {{ id: string; name: string; role: string; required: boolean; status: 'ok' | 'missing' | 'outdated'; version: string | null }} CheckResult */

/**
 * Classify a tool given its probed version triple (pure — unit-testable).
 * @param {Tool} tool
 * @param {Semver | null} triple
 * @returns {CheckResult}
 */
export function checkTool(tool, triple) {
  if (!triple) {
    return { id: tool.id, name: tool.name, role: tool.role, required: tool.required, status: 'missing', version: null };
  }
  const status = compareSemver(triple, tool.minVersion) < 0 ? 'outdated' : 'ok';
  return {
    id: tool.id,
    name: tool.name,
    role: tool.role,
    required: tool.required,
    status,
    version: triple.join('.'),
  };
}

/**
 * Probe every tool and classify it.
 * @returns {CheckResult[]}
 */
export function checkAll() {
  return TOOLS.map((tool) => checkTool(tool, lookupVersion(tool)));
}

/**
 * Detect the system package manager (used to pick the right install command).
 * @returns {string | null} 'brew' | 'apt' | 'dnf' | 'apk' | null.
 */
export function detectPackageManager() {
  for (const [id, bin] of /** @type {const} */ ([['brew', 'brew'], ['apt', 'apt-get'], ['dnf', 'dnf'], ['apk', 'apk']])) {
    try {
      execFileSync(bin, ['--version'], { stdio: 'ignore' });
      return id;
    } catch {
      /* keep looking */
    }
  }
  return null;
}

/**
 * Pick the shell command for a command-style install, per package manager.
 * @param {InstallSpec} install
 * @param {string | null} packageManager
 * @returns {string}
 */
export function commandFor(install, packageManager) {
  const commands = install.commands ?? {};
  return commands[packageManager ?? ''] ?? commands.default ?? '';
}

/** @typedef {{ tool: Tool; result: CheckResult; install: InstallSpec; command: string }} InstallStep */

/**
 * Build the ordered list of steps for tools that are missing or outdated.
 * @param {CheckResult[]} results
 * @param {{ skip?: string[] }} [options]
 * @returns {InstallStep[]}
 */
export function planSteps(results, options = {}) {
  const skip = new Set(options.skip ?? []);
  const byId = new Map(TOOLS.map((tool) => [tool.id, tool]));
  /** @type {InstallStep[]} */
  const steps = [];
  for (const result of results) {
    if (result.status === 'ok') continue;
    if (skip.has(result.id)) continue;
    const tool = byId.get(result.id);
    if (!tool) continue;
    steps.push({ tool, result, install: tool.install, command: '' });
  }
  // Node first (the engine itself), then registry order.
  steps.sort((a, b) => {
    if (a.tool.id === 'node') return -1;
    if (b.tool.id === 'node') return 1;
    return TOOLS.findIndex((t) => t.id === a.tool.id) - TOOLS.findIndex((t) => t.id === b.tool.id);
  });
  return steps;
}

/**
 * Download + verify + install a download-style tool into ~/.local/bin.
 * @param {InstallStep} step
 * @param {(line: string) => void} log
 * @returns {Promise<void>}
 */
export async function installDownload(step, log) {
  const binDir = join(homedir(), '.local', 'bin');
  mkdirSync(binDir, { recursive: true });
  const tmp = join(tmpdir(), `vibe-check-${step.tool.id}-${Date.now()}`);
  const url = step.install.url;
  if (!url) throw new Error(`${step.tool.id} has no download URL`);

  try {
    log(`  → downloading ${url}`);
    execFileSync('curl', ['-fsSL', '-o', tmp, url], { stdio: ['ignore', 'ignore', 'inherit'] });

    const hash = createHash('sha256').update(readFileSync(tmp)).digest('hex');
    if (hash !== step.install.sha256) {
      throw new Error(
        `checksum mismatch for ${step.tool.id}: expected ${step.install.sha256}, got ${hash}. Aborting — the download did not verify.`,
      );
    }
    log(`  ✓ checksum verified (${hash.slice(0, 12)}…)`);

    let source = tmp;
    if (step.install.archive === 'tar.gz') {
      execFileSync('tar', ['-xzf', tmp, '-C', tmpdir()], { stdio: ['ignore', 'ignore', 'inherit'] });
      source = join(tmpdir(), step.install.binary ?? step.tool.id);
    }

    const target = join(binDir, step.install.binary ?? step.tool.id);
    renameSync(source, target);
    chmodSync(target, 0o755);
    log(`  ✓ installed ${target}`);
  } finally {
    rmSync(tmp, { force: true, recursive: true });
  }
}

/**
 * Run a command-style install (prints the command first — transparency).
 * @param {string} command
 * @param {(line: string) => void} log
 * @returns {void}
 */
export function runCommandInstall(command, log) {
  log(`  → ${command}`);
  execFileSync('bash', ['-lc', command], { stdio: 'inherit' });
}

/**
 * Print the doctor report (read-only). Annotates tools THIS repo's stack
 * does not need (e.g. phpstan on a JS-only repo).
 * @param {{ color?: boolean; repoRoot?: string }} [options]
 * @returns {CheckResult[]}
 */
export function doctor(options = {}) {
  const color = options.color ?? true;
  const repoRoot = options.repoRoot ?? process.cwd();
  const stack = detectStackNeeds(repoRoot);
  /** @param {string} code @param {string} s @returns {string} */
  const paint = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const results = checkAll();

  console.log(`${ENGINE_NAME} ${ENGINE_VERSION} — onboarding check`);
  if (stack.anyStack) {
    const tags = [
      stack.js ? 'JS/TS' : '',
      stack.python ? 'Python' : '',
      stack.php ? 'PHP' : '',
      stack.go ? 'Go' : '',
      stack.docker ? 'Docker' : '',
    ].filter(Boolean);
    console.log(`stack detected: ${tags.join(' · ')}`);
  }
  console.log('');
  for (const result of results) {
    const mark =
      result.status === 'ok' ? paint('32', 'ok') : result.status === 'outdated' ? paint('33', 'outdated') : paint('31', 'missing');
    const version = result.version ?? '—';
    const flag = result.required ? '' : paint('90', ' (optional)');
    const need = toolNeed(result.id, stack);
    const needNote = !need.needed && stack.anyStack ? paint('90', ` (not needed here: ${need.reason})`) : '';
    console.log(`  ${mark.padEnd(color ? 15 : 9)}  ${result.name.padEnd(12)} ${version.padEnd(10)} ${result.role}${flag}${needNote}`);
  }
  console.log('');
  const missing = results.filter((r) => r.status !== 'ok').length;
  const rules = vendoredFreshness(VENDORED_MANIFEST, (m) => `@ ${String(m.pinnedSha ?? '').slice(0, 8)}`);
  if (rules) {
    const stale = rules.ageDays > RULESET_STALE_DAYS;
    const age = paint(stale ? '33' : '90', `${rules.ageDays} days old`);
    console.log(`  PHP rulesets: vendored ${rules.summary}, ${age}`);
    if (stale) {
      console.log(`    ${paint('33', 'consider refreshing: node scripts/vendor-php-rules.mjs')}`);
    }
  }
  const phpstan = vendoredFreshness(VENDORED_PHPSTAN_MANIFEST, (m) =>
    Object.entries(m.pinned ?? {}).map(([name, version]) => `${String(name).split('/')[1]}@${version}`).join(', '),
  );
  if (phpstan) {
    const stale = phpstan.ageDays > RULESET_STALE_DAYS;
    const age = paint(stale ? '33' : '90', `${phpstan.ageDays} days old`);
    console.log(`  PHPStan extensions: vendored ${phpstan.summary}, ${age}`);
    if (stale) {
      console.log(`    ${paint('33', 'consider refreshing: node scripts/vendor-phpstan-extensions.mjs')}`);
    }
  }
  console.log(missing === 0 ? paint('32', 'All prerequisites satisfied.') : `${missing} tool(s) need attention — run \`vibe-check setup\`.`);
  return results;
}

/**
 * Interactive onboarding (setup). Shows every step, asks, then installs.
 * Stack-aware: tools THIS repo's stack does not need are auto-skipped (with a
 * printed reason) unless `all` is set — install only what the scan will use.
 * @param {{ yes?: boolean; dryRun?: boolean; skip?: string[]; color?: boolean; all?: boolean; repoRoot?: string }} [options]
 * @returns {Promise<void>}
 */
export async function runOnboarding(options = {}) {
  const { yes = false, dryRun = false, skip = [], color = true, all = false } = options;
  const repoRoot = options.repoRoot ?? process.cwd();
  const stack = detectStackNeeds(repoRoot);
  /** @param {string} code @param {string} s @returns {string} */
  const paint = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const packageManager = detectPackageManager();

  console.log(`${ENGINE_NAME} ${ENGINE_VERSION} — onboarding`);
  console.log('Everything shown here is installed from official sources; commands print before they run.');
  if (stack.anyStack) {
    const tags = [
      stack.js ? 'JS/TS' : '',
      stack.python ? 'Python' : '',
      stack.php ? 'PHP' : '',
      stack.go ? 'Go' : '',
      stack.docker ? 'Docker' : '',
    ].filter(Boolean);
    console.log(`Stack detected: ${tags.join(' · ')} — tools this stack does not need are auto-skipped (override with --all).`);
  } else if (!all) {
    console.log('No language/container stack detected here — every tool stays a candidate.');
  }
  console.log('');

  const results = checkAll();
  const steps = planSteps(results, { skip });

  // Stack gate: auto-skip tools the detected stack cannot use.
  /** @type {InstallStep[]} */
  const active = [];
  /** @type {InstallStep[]} */
  const stackSkipped = [];
  for (const step of steps) {
    if (!all && stack.anyStack && !toolNeed(step.tool.id, stack).needed) {
      stackSkipped.push(step);
    } else {
      active.push(step);
    }
  }
  for (const step of stackSkipped) {
    const need = toolNeed(step.tool.id, stack);
    console.log(`${paint('90', '▸')} ${step.tool.name} — skipped: ${need.reason} (not needed for this stack)`);
  }
  if (stackSkipped.length > 0) console.log('');

  if (active.length === 0) {
    console.log(paint('32', 'All prerequisites satisfied — you are ready to run a scan.'));
    return;
  }

  if (dryRun) {
    console.log('Dry run — nothing will be installed. Planned steps:');
    for (const step of active) {
      printStep(step, packageManager, paint);
    }
    console.log('');
    console.log('Run `vibe-check setup` to install, or `--yes` to accept all.');
    return;
  }

  /** @type {{ tool: Tool; result: CheckResult; ok: boolean; skipped: boolean; failed: boolean }[]} */
  const summary = [];
  let acceptAll = yes;
  let quit = false;
  const rl = createInterface({ input: stdin, output: stdout });

  for (const step of active) {
    if (quit) break;

    printStep(step, packageManager, paint);

    if (step.install.kind === 'manual') {
      console.log(paint('33', '  (Node needs sudo on most systems — run the command yourself, or install from nodejs.org.)'));
      summary.push({ tool: step.tool, result: step.result, ok: false, skipped: true, failed: false });
      continue;
    }

    if (acceptAll) {
      await executeStep(step, packageManager, paint, summary);
      continue;
    }

    const answer = (await rl.question('  Install? [Y]es / [n]o / [s]kip / [a]ll remaining / [q]uit: ')).trim().toLowerCase();
    if (answer === 'q' || answer === 'quit') {
      console.log('Onboarding paused — re-run `vibe-check setup` to continue where you left off.');
      quit = true;
      summary.push({ tool: step.tool, result: step.result, ok: false, skipped: true, failed: false });
    } else if (answer === 'a' || answer === 'all') {
      acceptAll = true;
      await executeStep(step, packageManager, paint, summary);
    } else if (answer === 'y' || answer === 'yes' || answer === '') {
      await executeStep(step, packageManager, paint, summary);
    } else {
      // 'n' / 'no' / 's' / 'skip' — any other answer skips this tool.
      console.log(`  ⟳ skipped ${step.tool.name}`);
      summary.push({ tool: step.tool, result: step.result, ok: false, skipped: true, failed: false });
    }
  }
  rl.close();

  printSummary(summary, paint);
}

/**
 * @param {InstallStep} step
 * @param {string | null} packageManager
 * @param {(code: string, s: string) => string} paint
 */
function printStep(step, packageManager, paint) {
  const status = step.result.status === 'outdated' ? `outdated (${step.result.version ?? '?'})` : 'missing';
  console.log(`▸ ${step.tool.name} — ${step.tool.role}`);
  console.log(`  ${paint('31', status)} · ${step.install.summary}`);
  console.log(`  source: ${step.install.source}`);
  if (step.install.kind === 'download') {
    console.log(`  download: ${step.install.url}`);
    console.log(`  sha256:   ${step.install.sha256}`);
  } else if (step.install.kind === 'command') {
    console.log(`  command:  ${commandFor(step.install, packageManager)}`);
  }
}

/**
 * @param {InstallStep} step
 * @param {string | null} packageManager
 * @param {(code: string, s: string) => string} paint
 * @param {{ tool: Tool; result: CheckResult; ok: boolean; skipped: boolean; failed: boolean }[]} summary
 */
async function executeStep(step, packageManager, paint, summary) {
  try {
    if (step.install.kind === 'download') {
      await installDownload(step, (line) => console.log(line));
    } else if (step.install.kind === 'command') {
      const command = commandFor(step.install, packageManager);
      if (!command) throw new Error(`no install command for ${step.tool.id} on this system`);
      runCommandInstall(command, (line) => console.log(line));
    } else {
      throw new Error(`cannot auto-install ${step.tool.id}`);
    }
    console.log(`  ${paint('32', '✓')} ${step.tool.name} installed`);
    summary.push({ tool: step.tool, result: step.result, ok: true, skipped: false, failed: false });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.log(`  ${paint('31', '✗')} ${step.tool.name} failed: ${message}`);
    summary.push({ tool: step.tool, result: step.result, ok: false, skipped: false, failed: true });
  }
}

/**
 * @param {{ tool: Tool; result: CheckResult; ok: boolean; skipped: boolean; failed: boolean }[]} summary
 * @param {(code: string, s: string) => string} paint
 */
function printSummary(summary, paint) {
  console.log('');
  console.log('Onboarding summary');
  for (const entry of summary) {
    const mark = entry.ok ? paint('32', '✓') : entry.failed ? paint('31', '✗') : paint('33', '⟳');
    const note = entry.ok ? 'installed' : entry.failed ? 'failed' : 'skipped';
    console.log(`  ${mark} ${entry.tool.name.padEnd(12)} ${note}`);
  }
  console.log('');
  console.log('Tip: skipping is always safe — the engine reports a skipped provider in the report.');
}
