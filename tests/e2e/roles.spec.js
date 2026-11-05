const { test, expect } = require('@playwright/test');
const { USERS } = require('./utils/users');

test.describe('regular user', () => {
  test.use({ storageState: USERS.regular.state, extraHTTPHeaders: { 'X-Forwarded-For': USERS.regular.ip } });

  test('sees no admin navigation and cannot open admin pages', async ({ page }) => {
    await page.goto('/index.php');
    await expect(page.locator('nav').getByText('Regular User')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Users' })).toHaveCount(0);
    await page.goto('/admin/config_user.php');
    await expect(page).toHaveURL(/index\.php/);
  });

  test('networks above the own level cannot be selected', async ({ page }) => {
    // Regular User has level 5; "Datacenter" needs level 8.
    await page.goto('/extendedaccess.php');
    const row = page.getByRole('row', { name: /192\.168\.100\.0\/24/ });
    await expect(row.getByRole('checkbox')).toBeDisabled();
  });

  test('cannot call admin API actions', async ({ page }) => {
    await page.goto('/index.php');
    const status = await page.evaluate(async () => {
      const token = document.querySelector('meta[name="csrf-token"]').content;
      const resp = await fetch('api.php?f=revokeAccess', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ user_id: 1 }),
      });
      return resp.status;
    });
    expect(status).toBe(403);
  });
});

test('admin sees admin navigation', async ({ page }) => {
  await page.goto('/index.php');
  for (const name of ['Networks', 'Users', 'Logs', 'Config', 'Status']) {
    await expect(page.getByRole('link', { name, exact: true })).toBeVisible();
  }
});
