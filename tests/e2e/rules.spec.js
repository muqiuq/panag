const { test, expect } = require('@playwright/test');

// Detection rules editable in the web UI (admin/rules.php). Every test leaves the defaults behind.
async function resetRules(page) {
  await page.goto('/admin/rules.php');
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Reset all rules to defaults' }).click();
  await expect(page.getByTestId('rules-flash')).toContainText('back to their defaults');
}

test.afterEach(async ({ page }) => {
  await resetRules(page);
});

test('switch rules off, change severity and thresholds; alerts and config show it', async ({ page }) => {
  await page.goto('/admin/alerts.php');
  await page.getByRole('link', { name: 'Configure rules' }).click();
  await expect(page).toHaveURL(/admin\/rules\.php$/);

  const form = page.locator('#rules-form');
  await expect(form.getByLabel('U1 on')).toBeDisabled();
  await form.getByLabel('W7 on').uncheck();
  await form.getByLabel('W4 severity').selectOption('high');
  await form.locator('#rule-P1').getByLabel('Failed logins').fill('3');
  await form.locator('#rule-W5').getByLabel('Within').fill('45m');
  await form.getByRole('button', { name: 'Save rules' }).click();

  const flash = page.getByTestId('rules-flash');
  await expect(flash).toContainText('W7 off');
  await expect(flash).toContainText('W4 severity high');
  await expect(flash).toContainText('failed_logins 3');
  await expect(flash).toContainText('switch_window 45 min');
  await expect(page.locator('#rule-P1')).toContainText('3 failed PANAG logins from one IP');
  await expect(page.locator('#rule-P1').getByText('changed')).toBeVisible();
  await expect(page.locator('#rule-W7')).toHaveClass(/rule-off/);

  await page.goto('/admin/alerts.php');
  const reference = page.getByTestId('rule-reference');
  await expect(reference.locator('#rule-W7')).toContainText('off');
  await expect(reference.locator('#rule-W4')).toContainText('high');
  await expect(reference.locator('#rule-P1')).toContainText('3 failed PANAG logins');

  await page.goto('/admin/config.php');
  const row = page.locator('#configTable tbody tr').filter({ hasText: 'MONITOR_FAILED_LOGINS' }).first();
  await expect(row.getByTestId('rule-override')).toContainText('web 3');

  await page.goto('/admin/monitoring.php');
  await expect(page.getByText('Rules switched off')).toBeVisible();
  await expect(page.locator('dd').filter({ hasText: /^W7$/ })).toBeVisible();

  // the change is in the audit log (and reported by P6)
  await page.goto('/admin/logs.php?action=monitor_rules_changed');
  await expect(page.locator('#auditLogTable tbody')).toContainText('W7 off');
});

test('invalid values are refused with an explanation, nothing is stored', async ({ page }) => {
  await page.goto('/admin/rules.php');
  const form = page.locator('#rules-form');
  await form.locator('#rule-P1').getByLabel('Failed logins').fill('1');
  await form.locator('#rule-W2').getByLabel('Allowed countries').fill('Switzerland');
  await form.getByRole('button', { name: 'Save rules' }).click();

  const flash = page.getByTestId('rules-flash');
  await expect(flash).toContainText('Not saved');
  await expect(flash).toContainText('Failed logins (P1): a whole number from 2 to 1000.');
  await expect(flash).toContainText('"SWITZERLAND" is not an ISO country code');
  await expect(form.locator('#rule-P1').getByLabel('Failed logins')).toHaveValue('1'); // the input is kept for correction
  await page.goto('/admin/rules.php');
  await expect(page.locator('#rule-P1').getByText('changed')).toHaveCount(0);
});
