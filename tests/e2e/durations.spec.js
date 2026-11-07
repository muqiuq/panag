const { test, expect } = require('@playwright/test');
const { USERS } = require('./utils/users');
const { resetMock, addRouterEntry, remainingOnRouter, mockState } = require('./utils/mock');
const { toasts } = require('./utils/ui');

test.beforeEach(async () => { await resetMock(); });

test.describe('own durations (regular user)', () => {
  test.use({ storageState: USERS.regular.state, extraHTTPHeaders: { 'X-Forwarded-For': USERS.regular.ip } });

  test('user sets durations with presets and free input; grants use them', async ({ page }) => {
    await page.goto('/profile.php');
    const defaultField = page.locator('[data-duration-field]').filter({ has: page.getByLabel('Default access') });
    await defaultField.getByRole('button', { name: '2 h', exact: true }).click();
    await expect(page.getByLabel('Default access')).toHaveValue('2:00');
    await expect(defaultField.getByText(/valid until approx\./)).toBeVisible();
    await page.getByLabel('Extended access').fill('0:30');
    await page.getByRole('button', { name: 'Save durations' }).click();
    await expect(page.locator('#durations').getByRole('alert')).toContainText('Durations saved');
    await expect(page.getByLabel('Default access')).toHaveValue('2:00');
    await expect(page.getByLabel('Extended access')).toHaveValue('0:30');

    await page.goto('/index.php');
    await expect(page.getByText('for 2 h')).toBeVisible();
    await page.getByRole('button', { name: 'Grant default access' }).click();
    await expect(toasts(page)).toContainText('Default access granted until');
    const remaining = await remainingOnRouter('10.10.0.0/24');
    expect(remaining).toBeGreaterThan(7100);
    expect(remaining).toBeLessThanOrEqual(7200);
  });

  for (const [field, value, message] of [
    ['Default access', '15:00', 'Default access may be at most 14 h'],
    ['Extended access', '13:00', 'Extended access may be at most 12 h'],
    ['Default access', '0:10', 'Default access must be at least 15 min'],
    ['Extended access', 'tomorrow', 'Extended access: invalid duration'],
  ]) {
    test(`rejects ${field} = ${value}`, async ({ page }) => {
      await page.goto('/profile.php');
      await page.getByLabel(field).fill(value);
      const [resp] = await Promise.all([
        page.waitForResponse((r) => r.url().includes('profile.php') && r.request().method() === 'POST'),
        page.getByRole('button', { name: 'Save durations' }).click(),
      ]);
      expect(resp.status()).toBe(422);
      await expect(page.locator('#durations').getByRole('alert')).toContainText(message);
      await expect(page.getByLabel(field)).toHaveValue(value); // input is kept for correction
    });
  }

  test('the JSON API validates too', async ({ page }) => {
    await page.goto('/index.php');
    const result = await page.evaluate(async () => {
      const token = document.querySelector('meta[name="csrf-token"]').content;
      const resp = await fetch('api.php?f=savePrefs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ default_duration: '14:01', extended_duration: '0:15' }),
      });
      return { status: resp.status, body: await resp.json() };
    });
    expect(result.status).toBe(422);
    expect(result.body.errors[0]).toContain('at most 14 h');
  });
});

test.describe('active entries (admin)', () => {
  test('shows remaining time and revokes a single entry', async ({ page }) => {
    await addRouterEntry('Whitelist 127.0.0.1', '172.16.0.0/24', 'PANAG ext: VPN', '00:10:00');
    await page.goto('/index.php');
    await page.getByRole('button', { name: 'Grant default access' }).click();
    const rows = page.locator('#activeAccessTable tbody tr');
    const office = rows.filter({ hasText: 'Office LAN' });
    await expect(office).toContainText('Default');
    await expect(office).toContainText('1 h left');
    await expect(office.locator('td').nth(4)).toHaveText(/^\d\d:\d\d$/);
    await expect(rows.filter({ hasText: 'VPN' })).toContainText('Extended');

    await page.getByRole('button', { name: 'Revoke Office LAN' }).click();
    await expect(toasts(page)).toContainText('revoked');
    await expect(office).toHaveCount(0);
    const state = await mockState();
    expect(state.entries.map((e) => e.address)).toEqual(['172.16.0.0/24']);
  });

  test('extends an entry to the full duration of its kind', async ({ page }) => {
    await addRouterEntry('Whitelist 127.0.0.1', '172.16.0.0/24', 'PANAG ext: VPN', '00:02:00');
    await page.goto('/index.php');
    await page.getByRole('button', { name: 'Extend VPN' }).click();
    await expect(toasts(page)).toContainText('Extended until');
    const remaining = await remainingOnRouter('172.16.0.0/24');
    expect(remaining).toBeGreaterThan(880); // admin's extended duration: 15 min
  });

  test('a re-grant never shortens a longer active entry', async ({ page }) => {
    await addRouterEntry('Whitelist 127.0.0.1', '10.10.0.0/24', 'PANAG default: Office LAN', '05:00:00');
    await page.goto('/index.php');
    await page.getByRole('button', { name: 'Grant default access' }).click();
    await expect(toasts(page)).toContainText('Default access granted');
    expect(await remainingOnRouter('10.10.0.0/24')).toBeGreaterThan(4 * 3600);
  });

  test('expired entries disappear', async ({ page }) => {
    await addRouterEntry('Whitelist 127.0.0.1', '172.16.0.0/24', 'PANAG ext: VPN', '2s');
    await page.goto('/index.php');
    await expect(page.locator('#activeAccessTable')).toContainText('VPN');
    await page.waitForTimeout(2500);
    await page.reload();
    await expect(page.locator('#activeAccessTable')).toContainText('No active address list entries.');
  });
});
