const { test, expect } = require('@playwright/test');
const { loginAsLocalAdmin } = require('./utils/auth');

const EXT_NET = '172.16.0.0/24';

test('extended access applies selected networks', async ({ page }) => {
  await loginAsLocalAdmin(page);

  await page.getByRole('link', { name: 'Extended access' }).click();
  await expect(page).toHaveURL(/extendedaccess\.php/);

  const row = page.getByRole('row', { name: new RegExp(EXT_NET) });
  await row.getByRole('checkbox').check({ force: true });
  await page.getByRole('button', { name: 'Apply selection' }).click();

  await expect(page.getByRole('alert')).toContainText('Extended access applied');
  await expect(row.getByText('Yes')).toBeVisible();
});
