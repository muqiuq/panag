const { test, expect } = require('@playwright/test');
const { loginAsLocalAdmin } = require('./utils/auth');

function uniqueName() {
  return `E2E Network ${Date.now()}`;
}

test('admin can create and update network', async ({ page }) => {
  await loginAsLocalAdmin(page);
  await page.goto('/admin/config_networks.php');

  const name = uniqueName();
  const address = '10.199.0.0/24';

  await page.getByLabel('Name').first().fill(name);
  await page.getByLabel('Access level').first().fill('4');
  await page.getByLabel('Address').first().fill(address);
  await page.getByRole('button', { name: 'Add' }).click();

  await expect(page).toHaveURL(/config_networks\.php/);

  const row = page.getByRole('row').filter({ hasText: name });
  const accessInput = row.getByLabel('Access level');
  await accessInput.fill('7');
  await row.getByRole('button', { name: 'Save' }).click();

  await expect(page).toHaveURL(/config_networks\.php/);
  await expect(accessInput).toHaveValue('7');
});
