const { test, expect } = require('@playwright/test');
const { USER_IDS, SEEDED_DEFAULTS } = require('./utils/users');
const { toasts, setDefaults } = require('./utils/ui');

test.afterEach(async ({ page }) => {
  await page.goto('/index.php');
  await setDefaults(page, USER_IDS.regular, SEEDED_DEFAULTS.regular);
});

test('click a cell to toggle a default network', async ({ page }) => {
  await page.goto('/admin/matrix.php');
  const cell = page.getByRole('button', { name: 'VPN for Regular User' });
  await expect(cell).toHaveAttribute('aria-pressed', 'false');
  await cell.click();
  await expect(toasts(page)).toContainText('VPN added to the default networks of Regular User');
  await expect(cell).toHaveAttribute('aria-pressed', 'true');

  await page.reload();
  await expect(page.getByRole('button', { name: 'VPN for Regular User' })).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: 'VPN for Regular User' }).click();
  await expect(page.getByRole('button', { name: 'VPN for Regular User' })).toHaveAttribute('aria-pressed', 'false');
});

test('cells above the user level are locked', async ({ page }) => {
  await page.goto('/admin/matrix.php');
  const locked = page.getByRole('button', { name: 'Datacenter for Regular User' });
  await expect(locked).toBeDisabled();
  await expect(locked).toHaveAttribute('title', 'Requires L8 – Regular User has L5');
  await expect(page.getByRole('button', { name: 'Datacenter for Admin User' })).toHaveAttribute('aria-pressed', 'true');
});

test('filter users and networks', async ({ page }) => {
  await page.goto('/admin/matrix.php');
  const rows = page.locator('#matrixTable tbody tr:visible');
  await page.getByLabel('Filter users').fill('10.0.0.3');
  await expect(rows).toHaveCount(1);
  await expect(rows).toContainText('Super User');

  await page.getByLabel('Filter networks').fill('172.16');
  await expect(page.locator('#matrixTable thead th[data-network-col]:visible')).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'VPN for Super User' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Office LAN for Super User' })).toBeHidden();
});
