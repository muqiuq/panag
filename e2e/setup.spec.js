const { test, expect } = require('@playwright/test');
const { loginAsLocalAdmin } = require('./utils/auth');

test('setup page is disabled after flag', async ({ page }) => {
  await loginAsLocalAdmin(page);
  await page.goto('/setup.php');
  await expect(page).toHaveURL(/index\.php/);
});
