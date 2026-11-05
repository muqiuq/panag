const { test, expect } = require('@playwright/test');
const { resetMock, mockState } = require('./utils/mock');

const EXT_NET = '172.16.0.0/24';

test.beforeEach(async () => { await resetMock(); });

test('extended access applies selected networks', async ({ page }) => {
  await page.goto('/index.php');
  await page.getByRole('link', { name: 'Go to extended access' }).click();
  await expect(page).toHaveURL(/extendedaccess\.php/);

  const row = page.getByRole('row', { name: new RegExp(EXT_NET.replace(/\./g, '\\.')) });
  await row.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Apply selection' }).click();

  await expect(page.getByRole('alert')).toContainText('Extended access applied');
  await expect(row.getByText('Yes')).toBeVisible();

  const state = await mockState();
  const entry = state.entries.find((e) => e.address === EXT_NET);
  expect(entry.list).toBe('Whitelist 127.0.0.1');
  // EXTENDED_TIMEOUT is 15 minutes
  expect(entry.expires_at - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(900);
});
