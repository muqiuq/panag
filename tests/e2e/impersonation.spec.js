const { test, expect } = require('@playwright/test');
const { USERS } = require('./utils/users');

// Uses the second admin so the shared admin session of other tests is never touched.
test.use({ storageState: USERS.admin2.state, extraHTTPHeaders: { 'X-Forwarded-For': USERS.admin2.ip } });

test('admin can act as another user and return', async ({ page }) => {
  await page.goto('/admin/config_user.php');
  const card = page.locator('.card').filter({ has: page.locator('.card-header', { hasText: USERS.regular.ip }) });
  page.once('dialog', (dialog) => dialog.accept());
  await card.getByRole('button', { name: 'Impersonate' }).click();

  await expect(page).toHaveURL(/index\.php/);
  const banner = page.getByTestId('impersonation-banner');
  await expect(banner).toContainText('acting as Regular User');
  await expect(page.locator('nav').getByText('Regular User')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Users' })).toHaveCount(0);

  await banner.getByRole('button', { name: 'Back to admin' }).click();
  await expect(page).toHaveURL(/config_user\.php/);
  await expect(page.getByTestId('impersonation-banner')).toHaveCount(0);
  await expect(page.locator('nav').getByText('Admin User')).toBeVisible();

  await page.goto('/admin/logs.php?action=impersonate_end');
  await expect(page.getByRole('cell', { name: /Stopped acting as Regular User/ })).toBeVisible();
});

test('own account offers no impersonation', async ({ page }) => {
  await page.goto('/admin/config_user.php');
  const own = page.locator('.card').filter({ has: page.locator('.card-header', { hasText: USERS.admin2.ip }) });
  await expect(own.getByRole('button', { name: 'Impersonate' })).toHaveCount(0);
});
