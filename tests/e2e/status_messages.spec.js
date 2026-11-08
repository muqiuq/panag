const { test, expect } = require('@playwright/test');
const { OTP_SECRET, testIp } = require('./utils/users');
const { login } = require('./utils/auth');

// Status messages (PLAN.md, Phase 6): one per user, max. 100 characters, visible to everybody until 03:00.
const ADMIN_STATE = 'tests/e2e/.auth/admin.json';

/** Fresh users, so the messages do not show up next to the demo users of other specs. */
async function newUser(browser, label) {
  const admin = await browser.newContext({ storageState: ADMIN_STATE, extraHTTPHeaders: { 'X-Forwarded-For': '127.0.0.1' } });
  const page = await admin.newPage();
  const name = `E2E Status ${label} ${Date.now()}`;
  const ip = testIp();
  await page.goto('/admin/users.php');
  const form = page.locator('#add-user');
  await form.getByLabel('Name').fill(name);
  await form.getByLabel('User IP (login)').fill(ip);
  await form.getByLabel('Role').selectOption('user');
  await form.getByLabel('Access level').fill('5');
  await form.getByLabel('OTP secret (optional)').fill(OTP_SECRET);
  await form.getByRole('button', { name: 'Add user' }).click();
  await expect(page.getByRole('alert')).toContainText('User created');
  const id = Number(new URL(page.url()).searchParams.get('id'));
  await admin.close();
  return { name, ip, id };
}

async function loggedIn(browser, user) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders: { 'X-Forwarded-For': user.ip } });
  const page = await context.newPage();
  await login(page);
  return { context, page };
}

test('set, see and clear a status message; other users and admins see it', async ({ browser, page }) => {
  const alice = await newUser(browser, 'Alice');
  const bob = await newUser(browser, 'Bob');
  const a = await loggedIn(browser, alice);

  const input = a.page.getByLabel('Your status today');
  await input.fill('in the office until 5');
  await expect(a.page.locator('[data-status-count]')).toHaveText('21');
  await a.page.getByRole('button', { name: 'Save status' }).click();
  await expect(a.page.getByTestId('toasts')).toContainText('Status message saved – visible until 03:00.');
  const ownEntry = a.page.locator('#team-status li').filter({ hasText: alice.name });
  await expect(ownEntry).toContainText('in the office until 5');

  // another user sees it on the dashboard and on the status page
  const b = await loggedIn(browser, bob);
  await expect(b.page.locator('#team-status li').filter({ hasText: alice.name })).toContainText('in the office until 5');
  await b.page.goto('/status_public.php');
  await expect(b.page.locator('#publicStatusTable tbody tr').filter({ hasText: alice.name })).toContainText('in the office until 5');

  // the admin sees it in the users overview
  await page.goto('/index.php');
  await expect(page.locator('#usersOverviewTable tbody tr').filter({ hasText: alice.name })).toContainText('in the office until 5');

  // after a reload the field shows the own message; "Clear" removes it everywhere
  await a.page.reload();
  await expect(input).toHaveValue('in the office until 5');
  await a.page.getByRole('button', { name: 'Clear' }).click();
  await expect(a.page.getByTestId('toasts')).toContainText('Status message cleared.');
  await expect(input).toHaveValue('');
  await expect(ownEntry).toHaveCount(0);
  await b.page.goto('/index.php');
  await expect(b.page.locator('#team-status li').filter({ hasText: alice.name })).toHaveCount(0);

  await a.context.close();
  await b.context.close();
});

test('at most 100 characters; long words wrap instead of widening the page', async ({ browser, page }) => {
  const carol = await newUser(browser, 'Carol');
  const c = await loggedIn(browser, carol);
  const input = c.page.getByLabel('Your status today');
  await expect(input).toHaveAttribute('maxlength', '100');

  const tooLong = await c.page.evaluate(() => window.Panag.api('setStatusMessage', { message: 'x'.repeat(101) }));
  expect(tooLong.httpStatus).toBe(422);
  expect(tooLong.message).toContain('at most 100 are allowed');

  // one unbroken 100-character word, with a line break that is flattened
  const word = 'W'.repeat(100);
  const saved = await c.page.evaluate((text) => window.Panag.api('setStatusMessage', { message: text }), `${word}\n`);
  expect(saved.status).toBe(true);
  expect(saved.status_message).toBe(word);
  await c.page.reload();
  const entry = c.page.locator('#team-status li').filter({ hasText: carol.name });
  await expect(entry).toContainText(word);
  // No horizontal scrolling of the page; on failure, list what reaches beyond the viewport.
  const overflow = () => {
    const width = document.documentElement.clientWidth;
    if (document.documentElement.scrollWidth <= width) return [];
    return Array.from(document.querySelectorAll('body *'))
      .filter((el) => el.getBoundingClientRect().right > width + 1)
      .map((el) => `${el.tagName.toLowerCase()}.${el.className}`.slice(0, 80)).slice(0, 10);
  };
  expect(await c.page.evaluate(overflow)).toEqual([]);
  await c.page.setViewportSize({ width: 390, height: 800 });
  expect(await c.page.evaluate(overflow)).toEqual([]);

  // admin overview: the cell stays narrow
  await page.goto('/index.php');
  const cell = page.locator(`[data-status-of="${carol.id}"]`);
  await expect(cell).toHaveText(word);
  expect((await cell.boundingBox()).width).toBeLessThanOrEqual(22 * 16 + 1);

  await c.page.evaluate(() => window.Panag.api('setStatusMessage', { message: '' }));
  await c.context.close();
});
