const { test, expect } = require('@playwright/test');
const { loginAsLocalAdmin } = require('./utils/auth');

const DEFAULT_NET = '10.10.0.0/24';

test('grant default access populates address list', async ({ page }) => {
  await loginAsLocalAdmin(page);

  await expect(page.getByRole('button', { name: 'Grant default access' })).toBeEnabled();
  await page.getByRole('button', { name: 'Grant default access' }).click();

  await expect(page.getByRole('alert')).toContainText('Default access granted');
  await expect(page.getByText(DEFAULT_NET)).toBeVisible();
});
