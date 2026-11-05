const { test, expect } = require('@playwright/test');
const { resetMock, mockState } = require('./utils/mock');

const DEFAULT_NET = '10.10.0.0/24';

test.beforeEach(async () => { await resetMock(); });

test('grant default access creates the address-list entry on the router', async ({ page }) => {
  await page.goto('/index.php');
  await page.getByRole('button', { name: 'Grant default access' }).click();

  await expect(page.getByRole('alert')).toContainText('Default access granted');
  await expect(page.locator('#currentAccessContainer').getByText(DEFAULT_NET)).toBeVisible();

  const state = await mockState();
  const entry = state.entries.find((e) => e.list === 'Whitelist 127.0.0.1' && e.address === DEFAULT_NET);
  expect(entry, 'entry exists on mock router').toBeTruthy();
  expect(entry.comment).toBe('Office LAN');
  // DEFAULT_TIMEOUT is one hour
  const remaining = entry.expires_at - Math.floor(Date.now() / 1000);
  expect(remaining).toBeGreaterThan(3500);
  expect(remaining).toBeLessThanOrEqual(3600);
});
