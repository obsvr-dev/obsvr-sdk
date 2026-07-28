// Minimal, correctness-only ESLint flat config for the TypeScript SDK.
//
// Deliberately NOT a style linter: only rules that flag code that is
// almost certainly a bug are enabled. Formatting and stylistic
// preferences are out of scope.
import tseslint from 'typescript-eslint';

export default [
  {
    ignores: ['dist/**', 'node_modules/**', 'coverage/**'],
  },
  {
    files: ['**/*.ts', '**/*.js', '**/*.mjs'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
    },
    // Registered (with no rules enabled) so that inline
    // `eslint-disable @typescript-eslint/...` directives in the source
    // resolve; the correctness gate below is plugin-free on purpose.
    plugins: {
      '@typescript-eslint': tseslint.plugin,
    },
    // The inline disables target the full typescript-eslint rule set, which
    // this correctness-only gate does not enable; don't flag them as unused.
    linterOptions: {
      reportUnusedDisableDirectives: 'off',
    },
    rules: {
      // Duplicates that silently shadow each other
      'no-dupe-args': 'error',
      'no-dupe-keys': 'error',
      'no-dupe-else-if': 'error',
      'no-duplicate-case': 'error',

      // Dead or impossible code
      'no-unreachable': 'error',
      'no-constant-binary-expression': 'error',
      'no-self-assign': 'error',
      'no-self-compare': 'error',
      'no-sparse-arrays': 'error',

      // Comparison mistakes
      'use-isnan': 'error',
      'valid-typeof': 'error',
      'no-compare-neg-zero': 'error',
      'no-unsafe-negation': 'error',
      'no-cond-assign': ['error', 'except-parens'],

      // Async footguns
      'no-async-promise-executor': 'error',
      'require-atomic-updates': 'off', // too many false positives on queues

      // Assignment/loop mistakes
      'for-direction': 'error',
      'no-unmodified-loop-condition': 'error',
      'no-class-assign': 'error',
      'no-func-assign': 'error',
      'no-import-assign': 'error',
      'no-ex-assign': 'error',
      'getter-return': 'error',
      'no-setter-return': 'error',
    },
  },
];
