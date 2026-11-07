const { test, expect } = require('@playwright/test');
const { OTP_SECRET } = require('./utils/users');

function randomIp() {
  return `10.${10 + Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 200)}.10`;
}

async function createUser(page, { name, ip, role = 'user', level = '3', secret = '' }) {
  await page.goto('/admin/users.php');
  const form = page.locator('#add-user');
  await form.getByLabel('Name').fill(name);
  await form.getByLabel('User IP (login)').fill(ip);
  await form.getByLabel('Role').selectOption(role);
  await form.getByLabel('Access level').fill(level);
  await form.getByLabel('OTP secret (optional)').fill(secret);
  await form.getByRole('button', { name: 'Add user' }).click();
}

test('users list: sortable table without OTP secrets', async ({ page }) => {
  await page.goto('/admin/users.php');
  const table = page.locator('#usersTable');
  await expect(table.getByRole('link', { name: 'Regular User', exact: true })).toBeVisible();
  const regular = table.locator('tbody tr').filter({ hasText: '10.0.0.2' });
  await expect(regular).toContainText('User');
  await expect(regular).toContainText('L5');
  await expect(regular.locator('td').nth(4)).toContainText('2'); // Office LAN + Printers
  expect(await page.content()).not.toContain(OTP_SECRET);

  await page.getByLabel('Filter users').fill('super');
  await expect(table.locator('tbody tr:visible')).toHaveCount(1);
  await expect(table.locator('tbody tr:visible')).toContainText('Super User');
});

test('create a user: lands on the OTP tab, secret only after reveal (logged)', async ({ page }) => {
  const name = `E2E User ${Date.now()}`;
  const ip = randomIp();
  await createUser(page, { name, ip, role: 'superuser', level: '3' });

  await expect(page).toHaveURL(/admin\/user\.php\?id=\d+#otp/);
  await expect(page.getByRole('alert')).toContainText('User created');
  await expect(page.getByRole('tab', { name: 'OTP' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('heading', { name: new RegExp(name) })).toContainText('Superuser');

  const html = await page.content();
  await page.getByRole('button', { name: 'Reveal secret and QR code' }).click();
  await expect(page.locator('[data-otp-secret]')).toHaveText(/^[A-Z2-7]{32}$/);
  const secret = (await page.locator('[data-otp-secret]').textContent()).trim();
  expect(html).not.toContain(secret); // was not part of the page before "Reveal"
  await expect(page.getByRole('img', { name: 'QR code for the authenticator app' })).toBeVisible();
  await page.getByRole('button', { name: 'Hide' }).click();
  await expect(page.locator('[data-otp-secret]')).toBeHidden();

  await page.goto('/admin/logs.php?action=otp_revealed');
  await expect(page.getByRole('cell', { name: new RegExp(`OTP secret of ${name}`) })).toBeVisible();
});

test('replace the OTP secret', async ({ page }) => {
  const name = `E2E Otp ${Date.now()}`;
  await createUser(page, { name, ip: randomIp(), secret: OTP_SECRET });
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByLabel('New secret (Base32, empty = generate)').fill('not base32!');
  await page.getByRole('button', { name: 'Replace secret' }).click();
  await expect(page.getByRole('alert')).toContainText('OTP secret must be Base32');

  page.once('dialog', (dialog) => dialog.accept());
  await page.getByLabel('New secret (Base32, empty = generate)').fill('');
  await page.getByRole('button', { name: 'Replace secret' }).click();
  await expect(page.getByRole('alert')).toContainText('New OTP secret saved');
  await page.getByRole('button', { name: 'Reveal secret and QR code' }).click();
  await expect(page.locator('[data-otp-secret]')).toHaveText(/^[A-Z2-7]{32}$/);
  await expect(page.locator('[data-otp-secret]')).not.toHaveText(OTP_SECRET);
});

test('account tab: the server validates and clamps the access level', async ({ page }) => {
  await createUser(page, { name: `E2E Account ${Date.now()}`, ip: randomIp() });
  await page.getByRole('tab', { name: 'Account' }).click();
  await expect(page).toHaveURL(/#account$/);
  const level = page.getByLabel('Access level');
  await expect(level).toHaveValue('3');

  // Bypass the browser's max= validation to make sure the server enforces MAX_ACCESS_LEVEL.
  await level.evaluate((el) => el.removeAttribute('max'));
  await level.fill('99');
  await page.getByRole('button', { name: 'Save account' }).click();
  await expect(page.getByRole('alert')).toContainText('Account saved');
  await expect(level).toHaveValue('15');

  await page.getByLabel('User IP (login)').fill('10.0.0.2');
  await page.getByRole('button', { name: 'Save account' }).click();
  await expect(page.getByRole('alert')).toContainText('User IP 10.0.0.2 is already used by Regular User');
});

test('add user: duplicate IP and bad input are rejected with the input kept', async ({ page }) => {
  await createUser(page, { name: 'Dup', ip: '10.0.0.2' });
  await expect(page.locator('#add-user').getByRole('alert')).toContainText('already used by Regular User');
  await expect(page.locator('#add-user').getByLabel('Name')).toHaveValue('Dup');
});

test('durations tab: admin sets the durations of a user', async ({ page }) => {
  await createUser(page, { name: `E2E Durations ${Date.now()}`, ip: randomIp() });
  await page.getByRole('tab', { name: 'Durations' }).click();
  await page.getByLabel('Extended access').fill('2:00');
  await page.getByRole('button', { name: 'Save durations' }).click();
  await expect(page.getByRole('alert')).toContainText('Durations saved');
  await expect(page.getByRole('tab', { name: 'Durations' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByLabel('Extended access')).toHaveValue('2:00');

  await page.getByLabel('Extended access').fill('13:00');
  await page.getByRole('button', { name: 'Save durations' }).click();
  await expect(page.locator('#pane-durations').getByRole('alert')).toContainText('at most 12 h');
});

test('delete a user', async ({ page }) => {
  const name = `E2E Delete ${Date.now()}`;
  await createUser(page, { name, ip: randomIp() });
  await page.getByRole('tab', { name: 'Account' }).click();
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Delete user' }).click();
  await expect(page).toHaveURL(/admin\/users\.php/);
  await expect(page.getByRole('alert')).toContainText(`User ${name} deleted`);
  await expect(page.locator('#usersTable')).not.toContainText(name);
});
