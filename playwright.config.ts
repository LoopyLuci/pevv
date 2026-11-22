import { defineConfig, devices } from '@playwright/test';

/**
 * PEVV standalone web app e2e. Uses `localhost` (WebAuthn rejects IP rpIds)
 * on its own port so it never collides with another preview server.
 *   npm run build && npx playwright test --workers=3
 */
export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: /.*\.spec\.ts$/,
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  workers: 3,
  reporter: 'list',
  timeout: 90_000,
  use: { baseURL: 'http://localhost:4183', trace: 'retain-on-failure', ...devices['Desktop Chrome'] },
  webServer: {
    command: 'npx vite preview --host localhost --port 4183 --strictPort',
    url: 'http://localhost:4183',
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
