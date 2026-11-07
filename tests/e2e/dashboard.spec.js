const { test, expect } = require('@playwright/test');
const { resetMock, mockState } = require('./utils/mock');
const { as, toasts } = require('./utils/ui');

test.beforeEach(async () => { await resetMock(); });

test('all networks: grant a single network with the extended duration', async ({ page }) => {
  await page.goto('/index.php');
  const row = page.locator('#networksTable tbody tr').filter({ hasText: '172.16.0.0/24' });
  await row.getByRole('button', { name: 'Grant VPN' }).click();
  await expect(toasts(page)).toContainText(/VPN granted until \d\d:\d\d/);
  await expect(row).toContainText(/active, 15 min left/);
  await expect(page.locator('#activeAccessTable')).toContainText('VPN');

  const entry = (await mockState()).entries.find((e) => e.address === '172.16.0.0/24');
  expect(entry.list).toBe('Whitelist 127.0.0.1');
  expect(entry.comment).toBe('PANAG ext: VPN');
  expect(entry.expires_at - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(900);
});

test('the old extended access page redirects to the dashboard', async ({ page }) => {
  await page.goto('/extendedaccess.php');
  await expect(page).toHaveURL(/index\.php/);
});

test.describe('regular user', () => {
  test.use(as('regular'));

  test('networks above the own level are shown locked', async ({ page }) => {
    // Regular User has level 5; "Datacenter" needs level 8.
    await page.goto('/index.php');
    const row = page.locator('#networksTable tbody tr').filter({ hasText: '192.168.100.0/24' });
    await expect(row).toHaveClass(/network-locked/);
    await expect(row.getByRole('button', { name: /Grant Datacenter/ })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Grant VPN' })).toBeEnabled();
  });

  test('the API refuses networks above the own level', async ({ page }) => {
    await page.goto('/index.php');
    const status = await page.evaluate(async () => {
      const token = document.querySelector('meta[name="csrf-token"]').content;
      const resp = await fetch('api.php?f=grantNetwork', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ network_id: 5 }),
      });
      return resp.status;
    });
    expect(status).toBe(404);
    expect((await mockState()).entries).toHaveLength(0);
  });
});
