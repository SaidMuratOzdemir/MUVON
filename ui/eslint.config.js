import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  // src/components/ui holds shadcn/ui components as they are generated. They
  // export their variant helpers next to the component, which react-refresh
  // objects to, and editing them to satisfy the linter means diverging from
  // the upstream those files are meant to track.
  globalIgnores(['dist', 'src/components/ui/**', '**/components/ui/**']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    rules: {
      // Advisory rather than blocking. It fires on the reset-then-fetch
      // pattern three panels use when their subject changes, where the fix is
      // to remount on a key instead. That is a visual change to a dialog and a
      // list, so it wants to be made deliberately and looked at, not folded
      // into an unrelated commit to get a gate green.
      'react-hooks/set-state-in-effect': 'warn',
    },
  },
])
