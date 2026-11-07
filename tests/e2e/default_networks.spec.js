const { test, expect } = require('@playwright/test');
const { USER_IDS, NETWORKS, SEEDED_DEFAULTS } = require('./utils/users');
const { toasts, callApi, setDefaults } = require('./utils/ui');

// Admin edits the default networks of "Regular User" (L5; seeded: Office LAN, Printers).
test.afterEach(async ({ page }) => {
  await page.goto('/index.php');
  await setDefaults(page, USER_IDS.regular, SEEDED_DEFAULTS.regular);
});

test('user page, tab "Default networks": switches save immediately', async ({ page }) => {
  await page.goto(`/admin/user.php?id=${USER_IDS.regular}#networks`);
  await expect(page.getByRole('tab', { name: 'Default networks' })).toHaveAttribute('aria-selected', 'true');
  const pane = page.locator('#pane-networks');
  await expect(pane.getByLabel('Default: Office LAN')).toBeChecked();
  await expect(pane.getByText('2 selected')).toBeVisible();

  await pane.getByLabel('Default: VPN').check();
  await expect(toasts(page)).toContainText('VPN added to the default networks of Regular User');
  await expect(pane.getByText('3 selected')).toBeVisible();
  await page.reload();
  await expect(page.locator('#pane-networks').getByLabel('Default: VPN')).toBeChecked();

  await page.goto('/admin/logs.php?action=default_network_added');
  await expect(page.getByRole('cell', { name: /VPN \(172\.16\.0\.0\/24\) by Local Tester/ }).first()).toBeVisible();
});

test('networks above the level are hidden, "Show all" shows them locked', async ({ page }) => {
  await page.goto(`/admin/user.php?id=${USER_IDS.regular}#networks`);
  const pane = page.locator('#pane-networks');
  await expect(pane.getByLabel('Default: Datacenter')).toBeHidden();
  await pane.getByLabel(/Show all \(\d+ above L5\)/).check();
  const datacenter = pane.locator('tr').filter({ hasText: 'Datacenter' });
  await expect(datacenter).toBeVisible();
  await expect(datacenter).toHaveAttribute('title', 'Requires L8 – Regular User has L5');
  await expect(pane.getByLabel('Default: Datacenter')).toBeDisabled();

  // The API refuses it as well, also for admins.
  const resp = await callApi(page, 'setDefaultNetworks', { user_id: USER_IDS.regular, network_ids: [NETWORKS.datacenter], enabled: true });
  expect(resp.status).toBe(422);
  expect(resp.body.message).toContain('Datacenter requires level 8 (Regular User has level 5)');
});

test('search, "only selected" and select all / none', async ({ page }) => {
  await page.goto(`/admin/user.php?id=${USER_IDS.regular}#networks`);
  const pane = page.locator('#pane-networks');
  const visibleRows = pane.locator('tbody tr:visible');
  await expect(visibleRows).toHaveCount(3); // Office LAN, Printers, VPN (L ≤ 5)

  await pane.getByLabel('Only selected').check();
  await expect(visibleRows).toHaveCount(2);
  await pane.getByLabel('Only selected').uncheck();
  await pane.getByLabel('Search networks').fill('print');
  await expect(visibleRows).toHaveCount(1);
  await pane.getByLabel('Search networks').fill('');

  await pane.getByRole('button', { name: 'Select all' }).click();
  await expect(toasts(page)).toContainText('VPN added');
  await expect(pane.getByText('3 selected')).toBeVisible();
  await pane.getByRole('button', { name: 'Select none' }).click();
  await expect(toasts(page)).toContainText('3 networks removed');
  await expect(pane.getByText('0 selected')).toBeVisible();
  await expect(pane.getByRole('switch', { checked: true })).toHaveCount(0);
});

test('lowering the level marks defaults above it as invalid', async ({ page }) => {
  // Fresh user so the seeded users stay untouched.
  const ip = `10.${20 + Math.floor(Math.random() * 200)}.1.20`;
  await page.goto('/admin/users.php');
  const form = page.locator('#add-user');
  await form.getByLabel('Name').fill(`E2E Level ${Date.now()}`);
  await form.getByLabel('User IP (login)').fill(ip);
  await form.getByLabel('Access level').fill('5');
  await form.getByRole('button', { name: 'Add user' }).click();
  const userId = Number(new URL(page.url()).searchParams.get('id'));
  expect((await callApi(page, 'setDefaultNetworks', { user_id: userId, network_ids: [NETWORKS.office, NETWORKS.vpn], enabled: true })).status).toBe(200);

  await page.goto(`/admin/user.php?id=${userId}#account`);
  await page.getByLabel('Access level').fill('2');
  await page.getByRole('button', { name: 'Save account' }).click();
  await expect(page.getByRole('alert')).toContainText('1 default network(s) are above level L2 and will not be granted: VPN');

  await page.getByRole('tab', { name: /Default networks/ }).click();
  const vpn = page.locator('#pane-networks tr').filter({ hasText: 'VPN' });
  await expect(vpn).toBeVisible();
  await expect(vpn.getByText('Above level – not granted')).toBeVisible();
  await expect(page.locator('#pane-networks').getByText('1 above level (not granted)')).toBeVisible();

  await page.goto('/admin/users.php');
  await expect(page.locator('#usersTable tbody tr').filter({ hasText: ip })).toContainText('1 above level');

  // Removing an invalid default is always possible; afterwards it cannot be added again.
  await page.goto(`/admin/user.php?id=${userId}#networks`);
  await page.locator('#pane-networks').getByLabel('Default: VPN').uncheck();
  await expect(toasts(page)).toContainText('VPN removed');
  await expect(page.locator('#pane-networks').getByLabel('Default: VPN')).toBeHidden();
});
