const { test, expect } = require('@playwright/test');
const { totp } = require('./utils/totp');
const { OTP_SECRET, USERS } = require('./utils/users');

// Fresh, logged-out context acting as the dedicated login test user.
test.use({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders: { 'X-Forwarded-For': USERS.login.ip } });

test('wrong OTP is rejected', async ({ page }) => {
  await page.goto('/login.php');
  await page.getByLabel('One-Time Password').fill('000000');
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page.getByRole('alert')).toContainText('Invalid OTP');
});

test('login with OTP succeeds and the same code cannot be reused', async ({ page, context }) => {
  const otp = totp(OTP_SECRET);
  await page.goto('/login.php');
  await expect(page.getByRole('heading', { name: /Login to PANAG/i })).toBeVisible();
  await expect(page.locator('input[readonly]')).toHaveValue(USERS.login.ip);
  await page.getByLabel('One-Time Password').fill(otp);
  await page.getByRole('button', { name: 'Login' }).click();
  await page.waitForURL('**/index.php');
  await expect(page.locator('nav').getByText(USERS.login.name)).toBeVisible();

  // Replay protection: log out and try the same code again.
  await page.goto('/logout.php');
  await context.clearCookies();
  await page.goto('/login.php');
  await page.getByLabel('One-Time Password').fill(otp);
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page.getByRole('alert')).toContainText('Invalid OTP');
});

test('clients outside the login whitelist see nothing', async ({ browser }) => {
  const context = await browser.newContext({ extraHTTPHeaders: { 'X-Forwarded-For': '8.8.8.8' } });
  const page = await context.newPage();
  await page.goto('/login.php');
  await expect(page.getByText('There is nothing here.')).toBeVisible();
  await expect(page.getByLabel('One-Time Password')).toHaveCount(0);
  await context.close();
});
