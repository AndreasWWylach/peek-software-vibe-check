// Flat config for vibe-check's ESLint provider.
//
// Core rules only — no plugins, so the provider needs no dependency beyond a
// globally-installed `eslint`. Scoped to JS-family files: TypeScript requires
// typescript-eslint (deferred; TD-044 `no-floating-promises` lands with it).
export default [
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
