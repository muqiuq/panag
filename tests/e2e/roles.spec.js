const { test, expect } = require('@playwright/test');
const { USER_IDS, NETWORKS, SEEDED_DEFAULTS } = require('./utils/users');
const { as, toasts, callApi, setDefaults } = require('./utils/ui');

const ADMIN_PAGES = ['/admin/users.php', '/admin/user.php?id=3', '/admin/networks.php', '/admin/matrix.php', '/admin/logs.php', '/admin/status.php', '/admin/config.php', '/admin/alerts.php', '/admin/monitoring.php'];

test.describe('user', () => {
  test.use(as('regular'));

  test('sees no admin navigation and cannot open admin pages', async ({ page }) => {
    await page.goto('/index.php');
    await expect(page.locator('nav').getByText('Regular User')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Users' })).toHaveCount(0);
    for (const path of ADMIN_PAGES) {
      await page.goto(path);
      await expect(page, path).toHaveURL(/index\.php/);
    }
  });

  test('cannot call admin API actions', async ({ page }) => {
    await page.goto('/index.php');
    expect((await callApi(page, 'revokeAccess', { user_id: 1 })).status).toBe(403);
    expect((await callApi(page, 'revealOtp', { user_id: 1 })).status).toBe(403);
  });

  test('sees own default networks read-only and cannot change them', async ({ page }) => {
    await page.goto('/profile.php');
    await expect(page.getByTestId('profile-role')).toHaveText('User');
    await expect(page.getByText('managed by your admin')).toBeVisible();
    await expect(page.getByRole('switch')).toHaveCount(0);
    const own = await callApi(page, 'setDefaultNetworks', { network_ids: [NETWORKS.vpn], enabled: true });
    expect(own.status).toBe(403);
    expect(own.body.default_ids).toBeUndefined();
  });
});

test.describe('superuser', () => {
  test.use(as('superuser'));

  test.afterEach(async ({ browser }) => {
    // Restore the seeded defaults (as admin) for the other specs.
    const context = await browser.newContext(as('admin'));
    const page = await context.newPage();
    await page.goto('/index.php');
    await setDefaults(page, USER_IDS.superuser, SEEDED_DEFAULTS.superuser);
    await context.close();
  });

  test('has no admin navigation', async ({ page }) => {
    await page.goto('/index.php');
    await expect(page.locator('nav').getByText('Super User')).toBeVisible();
    await expect(page.locator('nav').getByText(/Superuser/)).toBeVisible();
    await expect(page.getByRole('link', { name: 'Users' })).toHaveCount(0);
    await page.goto('/admin/users.php');
    await expect(page).toHaveURL(/index\.php/);
  });

  test('chooses own default networks within the own level – saved immediately', async ({ page }) => {
    await page.goto('/profile.php');
    await expect(page.getByTestId('profile-role')).toHaveText('Superuser');
    // Level 8: Datacenter (L8) is offered, Core switches (L12) is hidden until "Show all", and locked.
    await expect(page.getByLabel('Default: Datacenter')).toBeVisible();
    await expect(page.getByLabel('Default: Core switches')).toBeHidden();
    await page.getByLabel('Show all (1 above L8)').check();
    await expect(page.getByLabel('Default: Core switches')).toBeDisabled();

    await page.getByLabel('Default: Office LAN').uncheck();
    await expect(toasts(page)).toContainText('Office LAN removed from your default networks');
    await page.getByLabel('Default: VPN').check();
    await expect(toasts(page)).toContainText('VPN added to your default networks');
    await page.getByLabel('Default: Datacenter').check();
    await expect(toasts(page)).toContainText('Datacenter added to your default networks');

    await page.reload();
    await expect(page.getByLabel('Default: VPN')).toBeChecked();
    await expect(page.getByLabel('Default: Office LAN')).not.toBeChecked();

    // The dashboard's default access card reflects the choice.
    await page.goto('/index.php');
    const card = page.locator('.card').filter({ has: page.getByText('Default access', { exact: true }) });
    await expect(card.getByText('172.16.0.0/24')).toBeVisible();
    await expect(card.getByText('192.168.100.0/24')).toBeVisible();
    await expect(card.getByText('10.10.0.0/24')).toHaveCount(0);
  });

  test('cannot add networks above the own level or touch other users (403)', async ({ page }) => {
    await page.goto('/profile.php');
    const above = await callApi(page, 'setDefaultNetworks', { network_ids: [NETWORKS.core], enabled: true });
    expect(above.status).toBe(422);
    expect(above.body.message).toContain('Core switches requires level 12');
    expect(above.body.default_ids).toEqual(SEEDED_DEFAULTS.superuser);

    const other = await callApi(page, 'setDefaultNetworks', { user_id: USER_IDS.regular, network_ids: [NETWORKS.vpn], enabled: true });
    expect(other.status).toBe(403);
    const otherRemove = await callApi(page, 'setDefaultNetworks', { user_id: USER_IDS.regular, network_ids: [NETWORKS.office], enabled: false });
    expect(otherRemove.status).toBe(403);
    // Unknown ids answer the same – no way to find out which users exist.
    expect((await callApi(page, 'setDefaultNetworks', { user_id: 9999, network_ids: [NETWORKS.vpn], enabled: true })).status).toBe(403);

    await page.goto('/index.php');
    await expect(page.getByText('10.255.0.0/28').first()).toBeVisible(); // listed in "All networks" …
    await expect(page.locator('.card').filter({ has: page.getByText('Default access', { exact: true }) }).getByText('10.255.0.0/28')).toHaveCount(0); // … but not a default
  });
});

test('admin sees admin navigation', async ({ page }) => {
  await page.goto('/index.php');
  for (const name of ['Profile', 'Users', 'Networks', 'Matrix', 'Logs', 'Config', 'Status']) {
    await expect(page.getByRole('link', { name, exact: true })).toBeVisible();
  }
});

test('old admin URLs redirect to the new pages', async ({ page }) => {
  for (const [from, to] of [['/admin/config_user.php', /admin\/users\.php/], ['/admin/config_networks.php', /admin\/networks\.php/], ['/admin/config_constants.php', /admin\/config\.php/]]) {
    await page.goto(from);
    await expect(page, from).toHaveURL(to);
  }
});
