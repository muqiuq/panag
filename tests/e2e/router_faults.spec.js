const { test, expect } = require('@playwright/test');
const { resetMock, setFault } = require('./utils/mock');

test.beforeEach(async () => { await resetMock(); });
test.afterEach(async () => { await setFault('none'); });

test('router errors are shown to the user', async ({ page }) => {
  await page.goto('/index.php');
  await setFault('500');
  await page.getByRole('button', { name: 'Grant default access' }).click();
  await expect(page.locator('#defaultAccessResult').getByRole('alert')).toContainText('API codes: 500');
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
