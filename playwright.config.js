// E2E tests run inside the Playwright container against the compose stack (./run.sh e2e).
const { defineConfig } = require('@playwright/test');

const BASE_URL = process.env.BASE_URL || 'http://127.0.0.1:18080';

module.exports = defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  expect: { timeout: 5000 },
  retries: process.env.CI ? 1 : 0,
  // Tests share router/DB state (one admin's address list) – run them in order.
  workers: 1,
  fullyParallel: false,
  reporter: process.env.CI ? [['github'], ['list'], ['html', { open: 'never' }]] : [['list'], ['html', { open: 'never' }]],
  globalSetup: require.resolve('./tests/e2e/global-setup.js'),
  use: {
    baseURL: BASE_URL,
    headless: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    // PANAG identifies users by source IP. The app trusts X-Forwarded-For from the
    // compose network (TRUSTED_PROXIES), so each test can act as a specific user.
    extraHTTPHeaders: { 'X-Forwarded-For': '127.0.0.1' },
    storageState: 'tests/e2e/.auth/admin.json',
  },
});
