const { test, expect } = require('@playwright/test');
const { loginAsLocalAdmin } = require('./utils/auth');

const DEFAULT_NET = '10.10.0.0/24';

test('admin can revoke address list entries', async ({ page }) => {
  await loginAsLocalAdmin(page);

  await page.getByRole('button', { name: 'Grant default access' }).click();
  await expect(page.getByRole('alert')).toContainText('Default access granted');
  await expect(page.getByText(DEFAULT_NET)).toBeVisible();

  const adminRow = page.getByRole('row').filter({ hasText: '127.0.0.1' }).first();
  const revokeButton = adminRow.getByRole('button', { name: 'Revoke all' });
  await page.once('dialog', (dialog) => dialog.accept());
  await revokeButton.click();

  const alert = page.getByRole('alert');
  await expect(alert).toContainText('Access revoked');
});
