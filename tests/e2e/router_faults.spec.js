const { test, expect } = require('@playwright/test');
const { resetMock, setFault, addRouterEntry } = require('./utils/mock');
const { toasts } = require('./utils/ui');

test.beforeEach(async () => { await resetMock(); });
test.afterEach(async () => { await setFault('none'); });

test('router errors are shown to the user', async ({ page }) => {
  await page.goto('/index.php');
  await setFault('500');
  await page.getByRole('button', { name: 'Grant default access' }).click();
  await expect(toasts(page).getByRole('alert')).toContainText('API codes: 500');
});

test('a router error does not hide the active access', async ({ page }) => {
  await addRouterEntry('Whitelist 127.0.0.1', '172.16.0.0/24', 'PANAG ext: VPN', '01:00:00');
  await page.goto('/index.php');
  await expect(page.locator('#activeAccessTable')).toContainText('VPN');
  await setFault('500');
  await page.getByRole('button', { name: 'Grant default access' }).click();
  await expect(toasts(page).getByRole('alert')).toContainText('API codes: 500');
  await expect(page.locator('#activeAccessTable')).toContainText('VPN'); // unknown ≠ none
  await expect(page.getByRole('button', { name: 'Revoke my access' })).toBeEnabled();

  await page.reload();
  await expect(page.getByText('The router is not reachable – your active access is unknown right now.')).toBeVisible();
});

test('admin status page reports an unreachable API', async ({ page }) => {
  await setFault('401');
  await page.goto('/admin/status.php');
  await expect(page.getByText('API error').first()).toBeVisible();
  await expect(page.getByText(/Failed to fetch identity/)).toBeVisible();
});

test('status page shows mock router data', async ({ page }) => {
  await page.goto('/admin/status.php');
  await expect(page.getByText('API OK').first()).toBeVisible();
  await expect(page.getByText('mock-router')).toBeVisible();
  // only peers of WIREGUARD_INTERFACE (wg0) are listed
  await expect(page.getByText('Demo laptop')).toBeVisible();
  await expect(page.getByText('Other interface')).toHaveCount(0);
});
