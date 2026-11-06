const { test, expect } = require('@playwright/test');
const { USERS } = require('./utils/users');

const as = (key) => ({ storageState: USERS[key].state, extraHTTPHeaders: { 'X-Forwarded-For': USERS[key].ip } });

/** POST the profile form directly (bypassing the UI) and return the HTTP status. */
async function postOwnDefaults(page, ids) {
  return page.evaluate(async (networkIds) => {
    const token = document.querySelector('meta[name="csrf-token"]').content;
    const body = new URLSearchParams({ csrf_token: token, action: 'save_default_networks' });
    networkIds.forEach((id) => body.append('network_ids[]', String(id)));
    const resp = await fetch('profile.php', { method: 'POST', body, redirect: 'manual' });
    // A redirect (= saved, PRG pattern) is reported by browsers as an opaque response with status 0.
    return resp.type === 'opaqueredirect' ? 302 : resp.status;
  }, ids);
}

test.describe('user', () => {
  test.use(as('regular'));

  test('sees no admin navigation and cannot open admin pages', async ({ page }) => {
    await page.goto('/index.php');
    await expect(page.locator('nav').getByText('Regular User')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Users' })).toHaveCount(0);
    for (const path of ['/admin/config_user.php', '/admin/config_networks.php', '/admin/logs.php', '/admin/status.php', '/admin/config_constants.php']) {
      await page.goto(path);
      await expect(page, path).toHaveURL(/index\.php/);
    }
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

  test('sees own default networks read-only and cannot change them', async ({ page }) => {
    await page.goto('/profile.php');
    await expect(page.getByTestId('profile-role')).toHaveText('User');
    await expect(page.getByText('managed by your admin')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save default networks' })).toHaveCount(0);
    expect(await postOwnDefaults(page, [1])).toBe(403);
  });
});

test.describe('superuser', () => {
  test.use(as('superuser'));

  test('has no admin navigation', async ({ page }) => {
    await page.goto('/index.php');
    await expect(page.locator('nav').getByText('Super User')).toBeVisible();
    await expect(page.locator('nav').getByText(/Superuser/)).toBeVisible();
    await expect(page.getByRole('link', { name: 'Users' })).toHaveCount(0);
    await page.goto('/admin/config_user.php');
    await expect(page).toHaveURL(/index\.php/);
  });

  test('chooses own default networks within the own level', async ({ page }) => {
    await page.goto('/profile.php');
    await expect(page.getByTestId('profile-role')).toHaveText('Superuser');
    // Level 8: Datacenter (L8) is offered, Core switches (L12) is not.
    await expect(page.getByLabel('Default: Datacenter')).toBeVisible();
    await expect(page.getByLabel('Default: Core switches')).toHaveCount(0);

    await page.getByLabel('Default: Office LAN').uncheck();
    await page.getByLabel('Default: VPN').check();
    await page.getByLabel('Default: Datacenter').check();
    await page.getByRole('button', { name: 'Save default networks' }).click();
    await expect(page.getByRole('alert')).toContainText('Default networks saved');
    await expect(page.getByLabel('Default: VPN')).toBeChecked();
    await expect(page.getByLabel('Default: Office LAN')).not.toBeChecked();

    // The dashboard's default access card reflects the choice.
    await page.goto('/index.php');
    const card = page.locator('.card').filter({ has: page.getByText('Default Access', { exact: true }) });
    await expect(card.getByText('172.16.0.0/24')).toBeVisible();
    await expect(card.getByText('192.168.100.0/24')).toBeVisible();
    await expect(card.getByText('10.10.0.0/24')).toHaveCount(0);
  });

  test('cannot sneak in networks above the own level', async ({ page }) => {
    await page.goto('/profile.php');
    // id 6 = "Core switches" (L12) from bin/seed-demo.php
    expect(await postOwnDefaults(page, [6])).toBe(302);
    await page.goto('/profile.php');
    await expect(page.getByRole('alert')).toContainText('above your access level were ignored');
    await page.goto('/index.php');
    await expect(page.getByText('10.255.0.0/28')).toHaveCount(0);
  });
});

test('admin sees admin navigation', async ({ page }) => {
  await page.goto('/index.php');
  for (const name of ['Profile', 'Networks', 'Users', 'Logs', 'Config', 'Status']) {
    await expect(page.getByRole('link', { name, exact: true })).toBeVisible();
  }
});
