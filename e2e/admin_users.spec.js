const { test, expect } = require('@playwright/test');
const { loginAsLocalAdmin } = require('./utils/auth');

function randomIp() {
  const a = 10 + Math.floor(Math.random() * 200);
  const b = Math.floor(Math.random() * 200);
  return `10.${a}.${b}.10`;
}

test('admin can create user and access level is clamped', async ({ page }) => {
  await loginAsLocalAdmin(page);
  await page.goto('/admin/config_user.php');

  const username = `E2E User ${Date.now()}`;
  const userIp = randomIp();
  const secret = 'JBSWY3DPEHPK3PXP';

  await page.getByLabel('Username (display)').first().fill(username);
  await page.getByLabel('User IP (login)').first().fill(userIp);
  await page.getByLabel('OTP secret (Base32)').first().fill(secret);
  const accessInput = page.getByLabel('Access level').first();
  await accessInput.fill('20');
  await page.getByRole('button', { name: 'Add user' }).click();

  await expect(page).toHaveURL(/config_user\.php/);

  const card = page.locator('.card').filter({ hasText: userIp });
  const cardAccess = card.getByLabel('Access level');
  await cardAccess.fill('99');
  await card.getByRole('button', { name: 'Save' }).click();

  await expect(page).toHaveURL(/config_user\.php/);
  await expect(cardAccess).toHaveValue('15');
});
