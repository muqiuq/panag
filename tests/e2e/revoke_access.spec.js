const { test, expect } = require('@playwright/test');
const { resetMock, mockState } = require('./utils/mock');
const { toasts } = require('./utils/ui');

const DEFAULT_NET = '10.10.0.0/24';

test.beforeEach(async () => { await resetMock(); });

test('user can revoke own access', async ({ page }) => {
  await page.goto('/index.php');
  await page.getByRole('button', { name: 'Grant default access' }).click();
  await expect(page.locator('#currentAccessContainer').getByText(DEFAULT_NET)).toBeVisible();

  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Revoke my access' }).click();
  await expect(toasts(page)).toContainText('Your access was revoked');
  await expect(page.getByText('No active address list entries.')).toBeVisible();
  expect((await mockState()).entries).toHaveLength(0);
});

test('admin can revoke address list entries of a user', async ({ page }) => {
  await page.goto('/index.php');
  await page.getByRole('button', { name: 'Grant default access' }).click();
  await expect(toasts(page)).toContainText('Default access granted');

  await page.reload();
  const adminRow = page.locator('#usersOverviewTable tbody tr').filter({ hasText: '127.0.0.1' });
  page.once('dialog', (dialog) => dialog.accept());
  await adminRow.getByRole('button', { name: 'Revoke all' }).click();
  await expect(toasts(page)).toContainText('Access of Local Tester revoked');
  expect((await mockState()).entries).toHaveLength(0);
});
