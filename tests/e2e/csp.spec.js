const { test, expect } = require('@playwright/test');
const { resetMock } = require('./utils/mock');
const { as } = require('./utils/ui');

// The Content-Security-Policy (docker/httpd.conf) forbids inline scripts and styles. Every page and its
// dynamic parts (palette, dialogs, QR code) must run without console errors or CSP violations.

/** Collect console errors, uncaught exceptions and CSP violation events of a page. */
async function watch(page) {
  const problems = [];
  page.on('console', (msg) => { if (msg.type() === 'error') problems.push(`console: ${msg.text()}`); });
  page.on('pageerror', (error) => problems.push(`exception: ${error.message}`));
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => {
      console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI} ${e.sourceFile}:${e.lineNumber}`);
    });
  });
  return problems;
}

async function usePalette(page) {
  await page.keyboard.press('Control+k');
  const combobox = page.getByRole('combobox').last();
  await expect(combobox).toBeFocused();
  await page.keyboard.type('o');
  await expect(page.locator('.palette-list [role="option"]').first()).toBeVisible();
  await page.keyboard.press('Escape');
}

test.beforeEach(async () => { await resetMock(); });

test('CSP header is sent', async ({ request }) => {
  const resp = await request.get('/login.php');
  const csp = resp.headers()['content-security-policy'];
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("style-src 'self'");
  expect(csp).not.toContain('unsafe-inline');
});

test('admin pages run without CSP errors', async ({ page }) => {
  const problems = await watch(page);
  for (const path of ['/index.php', '/profile.php', '/status_public.php', '/admin/users.php', '/admin/matrix.php', '/admin/logs.php', '/admin/config.php', '/admin/status.php']) {
    await page.goto(path);
    await usePalette(page);
  }

  await page.goto('/admin/networks.php');
  await page.getByRole('button', { name: 'Add network' }).click();
  const addDialog = page.getByRole('dialog', { name: 'Add network' });
  await expect(addDialog).toBeVisible();
  await addDialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(addDialog).toBeHidden();
  await page.getByRole('button', { name: 'Default users of VPN' }).click();
  await expect(page.getByRole('dialog', { name: 'Default for: VPN' })).toBeVisible();

  await page.goto('/admin/user.php?id=3#otp');
  await page.getByRole('button', { name: 'Reveal secret and QR code' }).click();
  await expect(page.getByRole('img', { name: 'QR code for the authenticator app' })).toBeVisible();
  for (const tab of ['Account', 'Default networks', 'Durations']) await page.getByRole('tab', { name: tab }).click();

  expect(problems).toEqual([]);
});

for (const role of ['regular', 'superuser']) {
  test.describe(role, () => {
    test.use(as(role));

    test('pages run without CSP errors', async ({ page }) => {
      const problems = await watch(page);
      for (const path of ['/index.php', '/profile.php', '/status_public.php']) {
        await page.goto(path);
        await usePalette(page);
      }
      expect(problems).toEqual([]);
    });
  });
}

test.describe('logged out', () => {
  test.use({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders: { 'X-Forwarded-For': '10.0.0.77' } });

  test('login page runs without CSP errors', async ({ page }) => {
    const problems = await watch(page);
    await page.goto('/login.php');
    await expect(page.getByLabel('One-Time Password')).toBeVisible();
    expect(problems).toEqual([]);
  });
});
