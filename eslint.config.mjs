import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'

// This project had no linter at all — not a broken one, none. `typecheck` is
// strict and the suite is thorough, which covers most of what a linter would,
// so the gate added here is deliberately narrow: rules that catch a bug, not
// rules that have an opinion about style. A linter that reports six hundred
// spacing preferences on its first run is a linter everybody learns to ignore,
// and then it is not catching the floating promise either.
//
// Specifically excluded: the stylistic and "recommended" sets that flag
// `any`, non-null assertions and unused vars in catch blocks. Those are
// judgement calls this codebase already makes deliberately in places, and
// arguing with them file by file is not worth the gate.
export default tseslint.config(
  {
    ignores: [
      // Anchored at the config's directory, so a bare 'out/**' misses build
      // output that lives one level down -- which is where it lives whenever a
      // git worktree is checked out inside the repo. CI never sees those, so a
      // clean run there says nothing about a run on a working machine.
      '**/out/**',
      '**/dist/**',
      '**/release/**',
      '**/node_modules/**',
      // Tooling state, not source: worktrees, agent scratch, local settings.
      '.claude/**',
      'resources/**',
      'scripts/**',
      '*.config.*',
      'eslint.config.mjs'
    ]
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // TypeScript already resolves every identifier, and does it knowing the
      // lib and DOM types each tsconfig pulls in. Leaving this on just means
      // maintaining a globals list by hand and getting 90 false positives for
      // `setTimeout` and `process` the first time anyone runs it.
      'no-undef': 'off',
      // Off: deliberate in this codebase and not a defect.
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-empty-function': 'off',
      // An empty catch is how several files say "a corrupt file is not fatal",
      // always with a comment saying so.
      'no-empty': ['error', { allowEmptyCatch: true }],
      // Underscore-prefixed args are the established signal for "required by
      // the signature, deliberately unused".
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' }
      ]
    }
  },
  {
    // The source already carries `eslint-disable-next-line
    // react-hooks/exhaustive-deps` comments in a dozen places. Without the
    // plugin those suppressions were inert AND an error, which is the worst of
    // both: the rule was not running and the comment said it was.
    //
    // exhaustive-deps earns its place here specifically. The bugs this codebase
    // actually produces are stale closures in polling hooks — an interval that
    // captured the first render's state and kept reporting it — and that is the
    // one thing this rule is good at.
    files: ['src/renderer/**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // A warning, not an error: a genuinely intentional omission is common
      // enough here that failing the build on it would push people to add the
      // disable comment reflexively, which is how the rule stops meaning
      // anything.
      'react-hooks/exhaustive-deps': 'warn'
    }
  },
  {
    // Tests reach into internals and re-import modules to reset state.
    files: ['tests/**'],
    rules: { '@typescript-eslint/no-require-imports': 'off' }
  }
)
