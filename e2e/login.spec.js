const { test, expect } = require('@playwright/test');
const { totp } = require('./utils/totp');

test('login with OTP succeeds for local tester', async ({ page }) => {
  await page.goto('/login.php');
  await expect(page.getByRole('heading', { name: /Login to PANAG/i })).toBeVisible();

  const otp = totp('JBSWY3DPEHPK3PXP');
  await page.getByLabel('One-Time Password').fill(otp);
  await page.getByRole('button', { name: 'Login' }).click();

  await page.waitForURL('**/index.php');
  await expect(page.getByText('Local Tester')).toBeVisible();
  await expect(page.getByText('127.0.0.1')).toBeVisible();
});
