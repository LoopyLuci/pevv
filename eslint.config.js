// Minimal ESLint 9 flat config: TypeScript recommended + React hooks rules.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['dist/**', 'dist-extension/**', 'dist-desktop/**', 'dist-extension-firefox/**', 'dist-extension-zips/**', 'desktop/src-tauri/target/**', 'desktop/src-tauri/gen/**', 'node_modules/**', 'test-results/**', 'playwright-report/**', 'coverage/**', '*.tmp.mjs'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
  { files: ['**/*.{js,mjs,cjs}'], languageOptions: { globals: { ...globals.browser, ...globals.node, ...globals.serviceworker } } },
);
