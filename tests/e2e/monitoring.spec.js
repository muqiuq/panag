const { test, expect } = require('@playwright/test');
const { OTP_SECRET, testIp } = require('./utils/users');
const { resetMock, mockState, setPeer, addRouterEntry } = require('./utils/mock');
const { waitForMail, mailsTo } = require('./utils/mail');
const { totp } = require('./utils/totp');
const { login } = require('./utils/auth');

// Security monitoring against the mock router (WireGuard peers), the GeoIP fixtures (dev/geoip), the fake AI
// and Mailpit. Every test uses its own user and peer, so retries and other specs cannot interfere.
const MONITOR_TOKEN = 'e2e-monitor-token'; // compose.dev.yml
const ADMIN_MAIL = 'security@example.test'; // ALERT_ADMIN_EMAILS
const CH = '198.51.100.40';
const US_HOSTING = '203.0.113.77'; // DigitalOcean in the fixture
const US = '198.18.1.20';

const rnd = () => Math.floor(Math.random() * 250) + 1;

async function runCycle(request) {
  const resp = await request.post('/monitor.php', { headers: { 'X-Monitor-Token': MONITOR_TOKEN } });
  expect(resp.status()).toBe(200);
  const stats = await resp.json();
  expect(stats.errors).toEqual([]);
  return stats;
}

/** Admin creates a user with e-mail address and a WireGuard peer connected from Switzerland. */
async function newMonitoredUser(page, request) {
  const name = `E2E Monitor ${Date.now()}`;
  const ip = testIp();
  const email = `user-${Date.now()}@example.test`;
  await page.goto('/admin/users.php');
  const form = page.locator('#add-user');
  await form.getByLabel('Name').fill(name);
  await form.getByLabel('User IP (login)').fill(ip);
  await form.getByLabel('Access level').fill('5');
  await form.getByLabel('OTP secret (optional)').fill(OTP_SECRET);
  await form.getByRole('button', { name: 'Add user' }).click();
  await page.getByRole('tab', { name: 'Account' }).click();
  await page.getByLabel('E-mail (security notifications)').fill(email);
  await page.getByRole('button', { name: 'Save account' }).click();
  await expect(page.getByRole('alert')).toContainText('Account saved');
  const key = `e2e-key-${Date.now()}-${rnd()}=`;
  await setPeer({ add: true, 'public-key': key, name: `Laptop of ${name}`, 'allowed-address': `${ip}/32`, 'current-endpoint-address': CH, 'last-handshake': '5s' });
  await runCycle(request); // learns CH for the user
  return { name, ip, email, key, id: Number(new URL(page.url()).searchParams.get('id')) };
}

async function userPage(browser, ip) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders: { 'X-Forwarded-For': ip } });
  const page = await context.newPage();
  await login(page);
  return { context, page };
}

test.beforeEach(async () => { await resetMock(); });

test('monitor.php runs only with the token', async ({ request }) => {
  expect((await request.get('/monitor.php')).status()).toBe(405);
  expect((await request.post('/monitor.php')).status()).toBe(403);
  expect((await request.post('/monitor.php', { headers: { 'X-Monitor-Token': 'wrong' } })).status()).toBe(403);
  const stats = await runCycle(request);
  expect(stats.status).toBe('ok');
  expect(stats.peers).toBeGreaterThan(0);
});

test('foreign hosting endpoint: alert with AI assessment, mails, and "That was me" teaches the place', async ({ page, request, browser }) => {
  const user = await newMonitoredUser(page, request);
  await setPeer({ 'public-key': user.key, 'current-endpoint-address': US_HOSTING });
  const stats = await runCycle(request);
  expect(stats.alerts).toBe(1);
  expect(stats.ai.assessed).toBe(1);

  // admin view
  await page.goto('/admin/alerts.php');
  const row = page.locator('#alertsTable tbody tr').filter({ hasText: user.name });
  await expect(row).toContainText('high');
  await expect(row).toContainText('W2, W3, W4');
  // server-side search and sorting (the list is paginated)
  await page.getByLabel('Search alerts').fill(user.name);
  await page.getByRole('button', { name: 'Show' }).click();
  await expect(page.locator('#alertsTable tbody tr')).toHaveCount(1);
  await expect(page.getByTestId('alerts-count')).toContainText('1 · page 1 of 1');
  await page.locator('#alertsTable thead').getByRole('link', { name: 'Severity' }).click();
  await expect(page).toHaveURL(/sort=severity/);
  await expect(page.getByLabel('Search alerts')).toHaveValue(user.name);
  await row.getByRole('link').first().click();
  await expect(page.getByText(/outside the allowed countries/)).toBeVisible();
  await expect(page.getByTestId('ai-assessment')).toContainText('Mock assessment');
  await expect(page.getByTestId('ai-assessment')).toContainText('via MockProvider');

  // mails: admins and the affected user
  const adminMail = await waitForMail({ to: ADMIN_MAIL, subject: user.name });
  expect(adminMail.subject).toMatch(/^\[PANAG\] HIGH:/);
  expect(adminMail.text).toContain('AI assessment');
  expect(adminMail.text).not.toContain(US_HOSTING); // public IPs are not copied into alerts
  const userMail = await waitForMail({ to: user.email, subject: 'Was this you?' });
  const link = userMail.text.match(/\/alert\.php\?id=\d+/)[0];

  // only pseudonymised facts went to the AI, with zero data retention
  const aiRequest = (await mockState()).ai.requests.at(-1);
  const sent = JSON.stringify(aiRequest);
  for (const secret of [user.name, user.ip, US_HOSTING, CH, user.key, user.email]) expect(sent).not.toContain(secret);
  expect(aiRequest.provider).toMatchObject({ zdr: true, data_collection: 'deny', only: ['MockProvider'], require_parameters: true });
  expect(aiRequest.response_format.type).toBe('json_schema');

  // the user confirms
  const { context, page: up } = await userPage(browser, user.ip);
  await expect(up.getByTestId('security-notice')).toContainText('Was this you?');
  await up.goto(link);
  await up.getByRole('button', { name: 'That was me' }).click();
  await expect(up.getByRole('alert')).toContainText('location is now known');
  await up.goto('/profile.php#places');
  await expect(up.locator('#places')).toContainText('US');
  await expect(up.locator('#places')).toContainText('AS14061');
  await expect(up.getByTestId('security-notice')).toHaveCount(0);
  await context.close();

  // the same place no longer alerts
  await setPeer({ 'public-key': user.key, 'current-endpoint-address': CH });
  await runCycle(request);
  await setPeer({ 'public-key': user.key, 'current-endpoint-address': US_HOSTING });
  expect((await runCycle(request)).alerts).toBe(0);
});

test('"That wasn\'t me" revokes the access and alerts the admins again', async ({ page, request, browser }) => {
  const user = await newMonitoredUser(page, request);
  await setPeer({ 'public-key': user.key, 'current-endpoint-address': US });
  expect((await runCycle(request)).alerts).toBe(1);
  const userMail = await waitForMail({ to: user.email, subject: 'Was this you?' });
  await addRouterEntry(`Whitelist ${user.ip}`, '10.10.0.0/24', 'PANAG ext: Office LAN', '01:00:00');

  const { context, page: up } = await userPage(browser, user.ip);
  await up.goto(userMail.text.match(/\/alert\.php\?id=\d+/)[0]);
  up.once('dialog', (dialog) => dialog.accept());
  await up.getByRole('button', { name: "That wasn't me" }).click();
  await expect(up.getByRole('alert')).toContainText('Your access was revoked');
  await context.close();
  expect((await mockState()).entries.filter((e) => e.list === `Whitelist ${user.ip}`)).toHaveLength(0);

  const before = (await mailsTo(ADMIN_MAIL)).length;
  await runCycle(request);
  const again = await waitForMail({ to: ADMIN_MAIL, subject: user.name, text: 'THIS WAS NOT ME' });
  expect(again.text).toContain('U1');
  expect((await mailsTo(ADMIN_MAIL)).length).toBe(before + 1);
  await page.goto('/admin/alerts.php');
  await expect(page.locator('#alertsTable tbody tr').filter({ hasText: user.name })).toContainText('not me');
});

test('a reused one-time password alerts at once; admins work through the status', async ({ page, request, browser }) => {
  const user = await newMonitoredUser(page, request);
  const code = totp(OTP_SECRET);
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders: { 'X-Forwarded-For': user.ip } });
  const up = await context.newPage();
  for (const expected of [/index\.php/, /login\.php/]) {
    await up.goto('/login.php');
    await up.getByLabel('One-Time Password').fill(code);
    await up.getByRole('button', { name: 'Login' }).click();
    await expect(up).toHaveURL(expected);
    await up.goto('/logout.php');
    await context.clearCookies();
  }
  await context.close();

  expect((await runCycle(request)).alerts).toBe(1);
  const mail = await waitForMail({ to: ADMIN_MAIL, subject: user.name });
  expect(mail.text).toContain('one-time password');

  await page.goto('/admin/alerts.php');
  const row = page.locator('#alertsTable tbody tr').filter({ hasText: user.name });
  // Rule codes explain themselves: tooltip in the list, reference table below it.
  await expect(row.getByRole('link', { name: 'P2' })).toHaveAttribute('title', 'Reused one-time password blocked');
  await expect(page.getByTestId('rule-reference').locator('#rule-P2')).toContainText('A one-time password is used a second time');
  await expect(page.getByTestId('rule-reference').locator('#rule-W2')).toContainText('outside the allowed countries (CH, DE)');
  await row.getByRole('link').first().click();
  await expect(page.getByRole('link', { name: 'What the rules mean' })).toBeVisible();
  await page.getByLabel('Status').selectOption('false_positive');
  await page.getByLabel('Comment').fill('Typed the code twice');
  await page.getByRole('button', { name: 'Save status' }).click();
  await expect(page.getByRole('alert')).toContainText('False positive');
  await expect(page.getByTestId('alert-status')).toHaveText('False positive');
  await expect(page.getByText('Typed the code twice')).toBeVisible();
});

test('monitoring page: status, peers, GeoIP, test mail and AI test', async ({ page, request }) => {
  await runCycle(request);
  await page.goto('/admin/monitoring.php');
  await expect(page.locator('#mainNav a[aria-current="page"]')).toHaveText('Monitoring');
  await expect(page.getByTestId('monitor-status')).toContainText('ok');
  await expect(page.getByTestId('geoip-country')).toContainText('DBIP-Country-Lite');
  await expect(page.getByTestId('geoip-asn')).toContainText('ASN');
  await expect(page.locator('#monitorPeersTable')).toContainText('peer1');
  await expect(page.locator('#monitorPeersTable')).toContainText('Regular User');

  const to = `test-${Date.now()}@example.test`;
  await page.getByLabel('Send a test mail to').fill(to);
  await page.getByRole('button', { name: 'Send test mail' }).click();
  await expect(page.getByRole('alert')).toContainText(`Test mail sent to ${to}`);
  await waitForMail({ to, subject: 'Test mail' });

  await page.getByRole('button', { name: 'Test AI with a synthetic case' }).click();
  await expect(page.getByTestId('ai-test-result')).toContainText('Mock assessment');
});

test('config page lists every setting, never shows secrets, admins only', async ({ page, browser }) => {
  await page.goto('/admin/config.php');
  const table = page.locator('#configTable');
  for (const name of ['MONITOR_TOKEN', 'SMTP_PASSWORD', 'OPENROUTER_API_KEY', 'SMTP_HOST', 'OPENROUTER_PROVIDERS', 'MAIL_FROM']) {
    await expect(table.locator('tr').filter({ hasText: name }).first()).toBeVisible();
  }
  await expect(table.locator('tr').filter({ hasText: 'SMTP_PASSWORD' })).toContainText('set');
  await expect(table.locator('tr').filter({ hasText: 'SMTP_HOST' })).toContainText('mailpit');
  await expect(page.getByTestId('config-warnings')).toHaveCount(0);
  const html = await page.content();
  for (const secret of ['e2e-secret-smtp-password', 'e2e-secret-openrouter-key', MONITOR_TOKEN]) expect(html).not.toContain(secret);

  const context = await browser.newContext({ storageState: 'tests/e2e/.auth/regular.json', extraHTTPHeaders: { 'X-Forwarded-For': '10.0.0.2' } });
  const regular = await context.newPage();
  for (const path of ['/admin/config.php', '/admin/alerts.php', '/admin/monitoring.php']) {
    await regular.goto(path);
    await expect(regular, path).toHaveURL(/index\.php/);
  }
  await context.close();
});

test('profile: e-mail address for notifications', async ({ browser }) => {
  const context = await browser.newContext({ storageState: 'tests/e2e/.auth/superuser.json', extraHTTPHeaders: { 'X-Forwarded-For': '10.0.0.3' } });
  const page = await context.newPage();
  await page.goto('/profile.php');
  await expect(page.getByTestId('monitoring-notice')).toContainText('Public IP addresses are kept for 30 days');
  await page.getByLabel('E-mail address').evaluate((el) => { el.type = 'text'; }); // bypass the browser check: the server validates
  await page.getByLabel('E-mail address').fill('not an address');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(page.locator('#contact').getByRole('alert')).toContainText('Not a valid e-mail address');
  await page.getByLabel('E-mail address').fill('super@example.test');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(page.locator('#contact').getByRole('alert')).toContainText('Notification settings saved');
  await expect(page.getByLabel('E-mail address')).toHaveValue('super@example.test');
  await context.close();
});
