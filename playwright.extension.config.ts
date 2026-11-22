import { defineConfig } from '@playwright/test';

/**
 * PEVV browser extension e2e. Loads the unpacked build into Chromium.
 *   npm run build:extension && npx playwright test -c pw.extension.config.ts
 * Headed with HEADED=1. Kept out of the default e2e run (its own testDir).
 */
export default defineConfig({
  testDir: 'tests/e2e-extension',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  timeout: 120_000,
  use: { trace: 'retain-on-failure' },
});
