const { test, expect } = require('@playwright/test');

function randomIp() {
  const a = 10 + Math.floor(Math.random() * 200);
  const b = Math.floor(Math.random() * 200);
  return `10.${a}.${b}.10`;
}

test('admin can create a user; the server clamps the access level', async ({ page }) => {
  await page.goto('/admin/config_user.php');

  const username = `E2E User ${Date.now()}`;
  const userIp = randomIp();

  await page.getByLabel('Username (display)').first().fill(username);
  await page.getByLabel('User IP (login)').first().fill(userIp);
  await page.getByLabel('OTP secret (Base32)').first().fill('JBSWY3DPEHPK3PXP');
  await page.getByLabel('Access level').first().fill('3');
  await page.getByLabel('Role').first().selectOption('superuser');
  await page.getByRole('button', { name: 'Add user' }).click();
  await expect(page).toHaveURL(/config_user\.php/);

  const card = page.locator('.card').filter({ has: page.locator('.card-header', { hasText: userIp }) });
  const cardAccess = card.getByLabel('Access level');
  await expect(cardAccess).toHaveValue('3');
  await expect(card.locator('.card-header')).toContainText('Superuser');
  await expect(card.getByLabel('Role')).toHaveValue('superuser');

  // Bypass the browser's max= validation to make sure the server enforces MAX_ACCESS_LEVEL.
  await cardAccess.evaluate((el) => el.removeAttribute('max'));
  await cardAccess.fill('99');
  await card.getByRole('button', { name: 'Save' }).click();

  await expect(page).toHaveURL(/config_user\.php/);
  await expect(cardAccess).toHaveValue('15');
});
