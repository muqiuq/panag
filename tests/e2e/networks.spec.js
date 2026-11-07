const { test, expect } = require('@playwright/test');
const { toasts } = require('./utils/ui');

const unique = (prefix) => `${prefix} ${Date.now()}`;
const row = (page, text) => page.locator('#networksAdminTable tbody tr').filter({ hasText: text });

async function addNetwork(page, name, address, level) {
  await page.goto('/admin/networks.php');
  await page.getByRole('button', { name: 'Add network' }).click();
  const dialog = page.getByRole('dialog', { name: 'Add network' });
  await dialog.getByLabel('Name').fill(name);
  await dialog.getByLabel('Address').fill(address);
  await dialog.getByLabel('Access level').fill(String(level));
  await dialog.getByRole('button', { name: 'Save network' }).click();
}

test('add and edit a network in the dialog', async ({ page }) => {
  const name = unique('E2E Network');
  await addNetwork(page, name, '10.199.0.0/24', 4);
  await expect(page.getByRole('alert')).toContainText(`Network ${name} saved`);
  await expect(row(page, name)).toContainText('L4');

  await row(page, name).getByRole('button', { name: `Edit ${name}` }).click();
  const dialog = page.getByRole('dialog', { name: `Edit ${name}` });
  await expect(dialog.getByLabel('Address')).toHaveValue('10.199.0.0/24');
  await dialog.getByLabel('Access level').fill('7');
  await dialog.getByRole('button', { name: 'Save network' }).click();
  await expect(row(page, name)).toContainText('L7');
  await expect(row(page, name)).toHaveCount(1);
});

test('the server rejects invalid addresses', async ({ page }) => {
  await page.goto('/admin/networks.php');
  await page.getByRole('button', { name: 'Add network' }).click();
  const dialog = page.getByRole('dialog', { name: 'Add network' });
  await dialog.getByLabel('Name').fill('Broken');
  const address = dialog.getByLabel('Address');
  await address.evaluate((el) => el.removeAttribute('pattern')); // bypass the browser's validation
  await address.fill('10.0.0.0/99');
  await dialog.getByRole('button', { name: 'Save network' }).click();
  await expect(page.getByRole('alert')).toContainText('Address must be an IPv4 network');
  await expect(row(page, 'Broken')).toHaveCount(0);
});

test('"Default for N users": reverse view, saved immediately, level enforced', async ({ page }) => {
  await page.goto('/admin/networks.php');
  // VPN (L5) is a seeded default of "Admin User" only.
  const vpn = row(page, '172.16.0.0/24');
  const button = vpn.getByRole('button', { name: 'Default users of VPN' });
  await expect(button).toHaveText('1 user');
  await button.click();
  const dialog = page.getByRole('dialog', { name: 'Default for: VPN' });
  await expect(dialog.getByLabel(/Admin User/)).toBeChecked();
  await expect(dialog.getByLabel(/Regular User/)).not.toBeChecked();
  await expect(dialog.getByLabel(/Login Tester/)).toHaveCount(0); // L1 < L5
  await dialog.getByLabel('Filter users').fill('regular');
  await expect(dialog.locator('li:visible')).toHaveCount(1);
  await dialog.getByLabel('Filter users').fill('');

  await dialog.getByLabel(/Regular User/).check();
  await expect(toasts(page)).toContainText('VPN added to the default networks of Regular User');
  await expect(button).toHaveText('2 users');

  await dialog.getByLabel(/Regular User/).uncheck();
  await expect(toasts(page)).toContainText('VPN removed from the default networks of Regular User');
  await expect(button).toHaveText('1 user');
  await dialog.getByRole('button', { name: 'Close' }).first().click();

  await page.reload();
  await expect(row(page, '172.16.0.0/24').getByRole('button', { name: 'Default users of VPN' })).toHaveText('1 user');
});

test('delete a network', async ({ page }) => {
  const name = unique('E2E Delete');
  await addNetwork(page, name, '10.198.0.0/24', 1);
  page.once('dialog', (dialog) => dialog.accept());
  await row(page, name).getByRole('button', { name: `Delete ${name}` }).click();
  await expect(page.getByRole('alert')).toContainText(`Network ${name} deleted`);
  await expect(row(page, name)).toHaveCount(0);
});
