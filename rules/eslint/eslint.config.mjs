// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// Flat config for vibe-check's ESLint provider.
//
// Core rules only — no plugins, so the provider needs no dependency beyond a
// globally-installed `eslint`. Scoped to JS-family files: TypeScript requires
// typescript-eslint (deferred; TD-044 `no-floating-promises` lands with it).
export default [
  {
    // Build output, caches, and vendored trees are not the app's own source —
    // linting them (e.g. minified bundles) produces pure noise. `node_modules`
    // is already ignored by ESLint's defaults; these are the rest.
    ignores: [
      '**/dist/**',
      '**/build/**',
      '**/.cache/**',
      '**/.next/**',
      '**/coverage/**',
      '**/.venv/**',
      '**/venv/**',
      '**/__pycache__/**',
      '**/.idea/**',
      '**/.vscode/**',
      '**/.turbo/**',
      '**/vendor/**',
    ],
  },
  {
    files: ['**/*.{js,mjs,cjs,jsx}'],
    rules: {
      'no-unused-vars': 'warn',
      'no-unreachable': 'error',
      'no-constant-condition': 'warn',
      'no-dupe-keys': 'error',
      'no-dupe-args': 'error',
    },
  },
];
