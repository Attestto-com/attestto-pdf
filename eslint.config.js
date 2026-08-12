// ESLint 9/10 flat config.
//
// This repo declared a `lint` script and has never had a config file or the
// TypeScript plugin installed, so `eslint src/ tests/` exited 2 with "couldn't
// find an eslint.config.js" on every invocation since the first commit. CI hid
// that behind `continue-on-error: true`, and `prepublishOnly` is
// `lint && typecheck && test && build`, so the publish gate could never reach
// its own later steps. A gate that cannot pass is not a gate.
//
// Copied from vc-sdk, where the same gap was closed first, so the rule set is
// identical across the estate and a fix in one place is portable.
//
// Deliberately narrow. This restores a lint step that runs and can fail; it is
// not the place to introduce a rule set nobody has reviewed, which would either
// bury the build in pre-existing violations or get switched off again.
//
// The `.vue` SFCs are not linted here. They ARE type-checked, by `vue-tsc` in
// the `typecheck` script, which is what caught nothing before because
// `typecheck` could not run either. Adding eslint-plugin-vue is a separate,
// reviewable change.
import js from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'node_modules/**',
      '*.config.js',
      '*.config.ts',
      'scripts/**',
      '**/*.vue',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // Tests assert on loosely-typed PDF and ASN.1 fixtures; `any` there is honest.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
)
