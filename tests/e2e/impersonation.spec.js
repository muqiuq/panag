const { test, expect } = require('@playwright/test');
const { USERS } = require('./utils/users');

// Uses the second admin so the shared admin session of other tests is never touched.
// Starting an impersonation regenerates the session id, so the stored admin2 session is gone afterwards:
// read-only checks run first.
test.use({ storageState: USERS.admin2.state, extraHTTPHeaders: { 'X-Forwarded-For': USERS.admin2.ip } });

test('own account offers no impersonation', async ({ page }) => {
  await page.goto('/admin/users.php');
  await expect(page.getByRole('button', { name: 'Impersonate Regular User' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Impersonate Admin User' })).toHaveCount(0);
  await page.goto('/admin/user.php?id=2');
  await expect(page.getByRole('button', { name: 'Impersonate' })).toHaveCount(0);
});

test('admin can act as another user and return', async ({ page }) => {
  await page.goto('/admin/users.php');
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Impersonate Regular User' }).click();

  await expect(page).toHaveURL(/index\.php/);
  const banner = page.getByTestId('impersonation-banner');
  await expect(banner).toContainText('acting as Regular User');
  await expect(page.locator('nav').getByText('Regular User')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Users' })).toHaveCount(0);

  await banner.getByRole('button', { name: 'Back to admin' }).click();
  await expect(page).toHaveURL(/admin\/users\.php/);
  await expect(page.getByTestId('impersonation-banner')).toHaveCount(0);
  await expect(page.locator('nav').getByText('Admin User')).toBeVisible();

  await page.goto('/admin/logs.php?action=impersonate_end');
  await expect(page.getByRole('cell', { name: /Stopped acting as Regular User/ })).toBeVisible();
});
