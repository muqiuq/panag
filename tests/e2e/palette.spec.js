const { test, expect } = require('@playwright/test');
const { resetMock, mockState, addRouterEntry, remainingOnRouter } = require('./utils/mock');
const { as, toasts } = require('./utils/ui');

// Default identity: admin "Local Tester" (L12, extended duration 15 min, default network Office LAN).
test.beforeEach(async () => { await resetMock(); });

const field = (page) => page.getByRole('combobox', { name: 'Grant access to a network' });
const selected = (page) => page.getByRole('listbox').getByRole('option', { selected: true });

test('keyboard only: type → Enter → ↓ → Enter grants the selected network', async ({ page }) => {
  await page.goto('/index.php');
  const input = field(page);
  await expect(input).toBeFocused(); // autofocus – no mouse needed

  await page.keyboard.type('10.10');
  const options = page.getByRole('listbox').getByRole('option');
  await expect(options).toHaveCount(2);
  await expect(input).toHaveAttribute('aria-expanded', 'true');
  await expect(options.filter({ has: page.locator('[aria-selected="true"]') })).toHaveCount(0);
  await expect(input).not.toHaveAttribute('aria-activedescendant', /.+/);

  // The first Enter only selects – an accidental Enter grants nothing.
  await page.keyboard.press('Enter');
  await expect(selected(page)).toContainText('Office LAN');
  await expect(input).toHaveAttribute('aria-activedescendant', /.+/);
  expect((await mockState()).entries).toHaveLength(0);

  await page.keyboard.press('ArrowDown');
  await expect(selected(page)).toContainText('Printers');
  await page.keyboard.press('Enter');

  await expect(toasts(page)).toContainText(/Printers granted until \d\d:\d\d/);
  await expect(input).toHaveValue('');
  await expect(input).toBeFocused();
  await expect(page.getByRole('listbox')).toBeHidden();
  await expect(page.locator('#activeAccessTable')).toContainText('Printers');

  const entry = (await mockState()).entries.find((e) => e.address === '10.10.5.0/24');
  expect(entry.comment).toBe('PANAG ext: Printers');
  const remaining = await remainingOnRouter('10.10.5.0/24');
  expect(remaining).toBeGreaterThan(850); // extended duration, also for default networks
  expect(remaining).toBeLessThanOrEqual(900);
});

test('mouse: hover selects, click grants', async ({ page }) => {
  await page.goto('/index.php');
  await page.mouse.move(5, 5); // the pointer is somewhere on the page
  await field(page).fill('data');
  const option = page.getByRole('option', { name: /Datacenter/ });
  await option.hover();
  await expect(option).toHaveAttribute('aria-selected', 'true');
  await option.click();
  await expect(toasts(page)).toContainText('Datacenter granted until');
  expect((await mockState()).entries.map((e) => e.address)).toEqual(['192.168.100.0/24']);
});

test('a list appearing under a resting pointer selects nothing', async ({ page }) => {
  await page.goto('/index.php');
  const box = await field(page).boundingBox();
  await page.mouse.move(box.x + 60, box.y + box.height + 25); // where the first option will appear
  await field(page).focus();
  await page.keyboard.type('10.10');
  await expect(page.getByRole('listbox').getByRole('option')).toHaveCount(2);
  await page.waitForTimeout(300); // let the browser dispatch its hover updates
  await expect(selected(page)).toHaveCount(0);
  await page.keyboard.press('Enter');
  await expect(selected(page)).toContainText('Office LAN'); // still only selected …
  expect((await mockState()).entries).toHaveLength(0); // … not granted
});

test('an IP address finds the network containing it', async ({ page }) => {
  await page.goto('/index.php');
  await field(page).fill('10.10.5.7');
  const options = page.getByRole('listbox').getByRole('option');
  await expect(options).toHaveCount(1);
  await expect(options.first()).toContainText('Printers');
  await expect(options.first()).toContainText('10.10.5.0/24');
});

test('fuzzy name with a duration: "dc 2h"', async ({ page }) => {
  await page.goto('/index.php');
  await field(page).fill('dc 2h');
  const first = page.getByRole('listbox').getByRole('option').first();
  await expect(first).toContainText('Datacenter');
  await expect(first).toContainText('Grant · 2 h');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await expect(toasts(page)).toContainText('Datacenter granted until');
  const remaining = await remainingOnRouter('192.168.100.0/24');
  expect(remaining).toBeGreaterThan(7100);
  expect(remaining).toBeLessThanOrEqual(7200);
});

test('a duration above the limit is refused', async ({ page }) => {
  await page.goto('/index.php');
  await field(page).fill('vpn 13h');
  await expect(page.getByRole('option', { name: /VPN/ })).toContainText('Duration must be at most 12 h');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await expect(toasts(page).getByRole('alert')).toContainText('Extended access may be at most 12 h');
  await expect(field(page)).toHaveValue('vpn 13h'); // kept for correction
  expect((await mockState()).entries).toHaveLength(0);
});

test('overlay: a failed action keeps the dialog open and shows the error inside it', async ({ page }) => {
  await page.goto('/profile.php');
  await page.keyboard.press('/');
  const dialog = page.getByTestId('palette-dialog');
  await page.keyboard.type('vpn 13h');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await expect(dialog.getByRole('alert')).toContainText('at most 12 h');
  await expect(dialog.getByRole('combobox')).toHaveValue('vpn 13h');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await page.keyboard.type('2h');
  await expect(dialog.getByRole('alert')).toBeHidden();
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
  await expect(toasts(page)).toContainText('VPN granted until');
});

test('Enter on an active network extends it', async ({ page }) => {
  await addRouterEntry('Whitelist 127.0.0.1', '172.16.0.0/24', 'PANAG ext: VPN', '00:02:00');
  await page.goto('/index.php');
  await field(page).fill('vpn');
  const option = page.getByRole('option', { name: /VPN/ });
  await expect(option).toContainText('active, 2 min left');
  await expect(option).toContainText('Extend · 15 min');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await expect(toasts(page)).toContainText('VPN granted until');
  expect(await remainingOnRouter('172.16.0.0/24')).toBeGreaterThan(850);
});

test('Esc closes the list, a second Esc clears the field', async ({ page }) => {
  await page.goto('/index.php');
  await field(page).fill('office');
  await expect(page.getByRole('listbox')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('listbox')).toBeHidden();
  await expect(field(page)).toHaveValue('office');
  await page.keyboard.press('Escape');
  await expect(field(page)).toHaveValue('');
});

test('commands: grant default access', async ({ page }) => {
  await page.goto('/index.php');
  await field(page).fill('default');
  await expect(page.getByRole('option', { name: /Grant default access/ })).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(selected(page)).toContainText('Grant default access');
  await page.keyboard.press('Enter');
  await expect(toasts(page)).toContainText('Default access granted until');
  expect((await mockState()).entries.map((e) => e.comment)).toEqual(['PANAG default: Office LAN']);
});

test('admin: "Find user" opens the user page', async ({ page }) => {
  await page.goto('/index.php');
  await field(page).fill('regular');
  await page.getByRole('option', { name: /User: Regular User/ }).click();
  await expect(page).toHaveURL(/admin\/user\.php\?id=3/);
});

test('overlay on every page: "/" and Ctrl+K', async ({ page }) => {
  await page.goto('/profile.php');
  const dialog = page.getByTestId('palette-dialog');
  await page.keyboard.press('/');
  await expect(dialog).toBeVisible();
  const input = dialog.getByRole('combobox', { name: 'Search networks and commands' });
  await expect(input).toBeFocused();
  await page.keyboard.type('office');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
  await expect(toasts(page)).toContainText('Office LAN granted until');
  expect((await mockState()).entries.map((e) => e.address)).toEqual(['10.10.0.0/24']);

  await page.keyboard.press('Control+k');
  await expect(dialog).toBeVisible();
  await expect(input).toHaveValue('');
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();

  // "/" while typing in a field is just a character.
  await page.getByLabel('Default access').fill('');
  await page.getByLabel('Default access').press('/');
  await expect(dialog).toBeHidden();
});

test.describe('regular user', () => {
  test.use(as('regular'));

  test('only networks within the own level, no admin commands', async ({ page }) => {
    await page.goto('/index.php');
    await field(page).fill('data');
    await expect(page.getByText('No matching network or command.')).toBeVisible();
    await field(page).fill('go to');
    await expect(page.getByRole('option', { name: /Go to Users/ })).toHaveCount(0);
    await field(page).fill('vpn');
    await expect(page.getByRole('option', { name: /VPN/ })).toBeVisible();
  });
});
