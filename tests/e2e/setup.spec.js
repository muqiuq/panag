const { test, expect } = require('@playwright/test');

test('setup page is closed once an admin exists', async ({ page }) => {
  await page.goto('/setup.php');
  await expect(page).toHaveURL(/index\.php/);
});

test('setup page is closed for anonymous visitors too', async ({ browser }) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders: { 'X-Forwarded-For': '10.0.0.77' } });
  const page = await context.newPage();
  await page.goto('/setup.php');
  await expect(page).not.toHaveURL(/setup\.php/);
  await context.close();
});
