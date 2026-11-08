const { test, expect } = require('@playwright/test');
const axe = require('@axe-core/playwright');
const { OTP_SECRET, testIp } = require('./utils/users');
const { login } = require('./utils/auth');

const AxeBuilder = axe.default || axe.AxeBuilder;

// Themes (src/themes.php): choice on the profile page and in the command palette, stored per user, mirrored into
// a cookie for the login page. Every theme gets screenshots of the main pages (visual smoke test, attached to the
// report) and an axe contrast check: WCAG AAA for the high-contrast themes, AA for the others.
const THEMES = {
  default: { label: 'Default', dark: false },
  dark: { label: 'Dark mode', dark: true },
  'high-contrast': { label: 'High contrast', dark: false, aaa: true },
  'high-contrast-dark': { label: 'High contrast dark', dark: true, aaa: true },
  slay: { label: 'Slay', dark: false },
  switzerland: { label: 'Switzerland', dark: false },
  terminal: { label: 'Terminal', dark: true },
  brasil: { label: 'Brasil', dark: false },
  'atomic-age': { label: 'Atomic age', dark: false },
  wtf: { label: 'WTF', dark: false },
  suse: { label: 'SUSE Linux', dark: false },
  win95: { label: 'Windows 95', dark: false },
  winxp: { label: 'Windows XP', dark: false },
  ubuntu: { label: 'Ubuntu', dark: false },
  amiga: { label: 'Amiga', dark: true },
};
const ADMIN_STATE = 'tests/e2e/.auth/admin.json';

/** The admin creates a fresh account (theme tests change and log out their own user only). */
async function newUser(browser, role = 'user') {
  const admin = await browser.newContext({ storageState: ADMIN_STATE, extraHTTPHeaders: { 'X-Forwarded-For': '127.0.0.1' } });
  const page = await admin.newPage();
  const name = `E2E Theme ${role} ${Date.now()}`;
  const ip = testIp();
  await page.goto('/admin/users.php');
  const form = page.locator('#add-user');
  await form.getByLabel('Name').fill(name);
  await form.getByLabel('User IP (login)').fill(ip);
  await form.getByLabel('Role').selectOption(role);
  await form.getByLabel('Access level').fill('10');
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

/** The radios are visually hidden (Bootstrap .btn-check) – users click the tile. */
const pickTheme = (page, theme) => page.locator(`label[for="theme-${theme}"]`).click();
const themeRadio = (page, label) => page.getByRole('radio', { name: label, exact: true });

async function expectTheme(page, theme) {
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await expect(page.locator('html')).toHaveAttribute('data-bs-theme', THEMES[theme].dark ? 'dark' : 'light');
}

test('profile: live preview, saved per user, also on the login page after logout', async ({ browser }) => {
  const user = await newUser(browser);
  const { context, page } = await loggedIn(browser, user);
  await page.goto('/profile.php');
  await expectTheme(page, 'default');

  await pickTheme(page, 'dark');
  await expectTheme(page, 'dark'); // live preview, not saved yet
  await expect(page.getByText('Preview – save to keep this theme.')).toBeVisible();
  await page.reload();
  await expectTheme(page, 'default');

  await pickTheme(page, 'high-contrast-dark');
  await page.getByRole('button', { name: 'Save theme' }).click();
  await expect(page.getByRole('alert')).toContainText('Theme set to High contrast dark.');
  await expectTheme(page, 'high-contrast-dark');
  await expect(themeRadio(page, 'High contrast dark')).toBeChecked();
  await page.goto('/index.php');
  await expectTheme(page, 'high-contrast-dark');

  await page.goto('/logout.php');
  await page.goto('/login.php');
  await expectTheme(page, 'high-contrast-dark');
  await context.close();

  // Other users keep their own theme.
  const other = await browser.newContext({ storageState: ADMIN_STATE, extraHTTPHeaders: { 'X-Forwarded-For': '127.0.0.1' } });
  const adminPage = await other.newPage();
  await adminPage.goto('/index.php');
  await expectTheme(adminPage, 'default');
  await other.close();
});

test('command palette: "Theme: Slay" switches without a reload and is kept', async ({ browser }) => {
  const user = await newUser(browser);
  const { context, page } = await loggedIn(browser, user);
  await page.goto('/profile.php');
  await page.evaluate(() => { window.noReload = true; });
  await page.keyboard.press('/');
  const dialog = page.getByTestId('palette-dialog');
  await page.keyboard.type('theme slay');
  await expect(dialog.getByRole('option').first()).toContainText('Theme: Slay');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await expect(page.getByTestId('toasts')).toContainText('Theme: Slay.');
  await expectTheme(page, 'slay');
  expect(await page.evaluate(() => window.noReload)).toBe(true);
  await page.reload();
  await expectTheme(page, 'slay');
  await expect(themeRadio(page, 'Slay')).toBeChecked();
  await context.close();
});

test('an unknown theme is refused', async ({ page }) => {
  await page.goto('/index.php');
  const resp = await page.evaluate(() => window.Panag.api('setTheme', { theme: 'rainbow' }));
  expect(resp.status).toBe(false);
  expect(resp.httpStatus).toBe(422);
  await page.reload();
  await expectTheme(page, 'default');
});

test.describe('every theme on the main pages: screenshots and contrast', () => {
  let admin;

  test.beforeAll(async ({ browser }) => {
    admin = await newUser(browser, 'admin');
    const { context } = await loggedIn(browser, admin);
    admin.state = await context.storageState();
    await context.close();
  });

  for (const [theme, meta] of Object.entries(THEMES)) {
    test(`theme ${theme}`, async ({ browser }, testInfo) => {
      test.setTimeout(90_000);
      const context = await browser.newContext({ storageState: admin.state, extraHTTPHeaders: { 'X-Forwarded-For': admin.ip } });
      const page = await context.newPage();
      await page.goto('/profile.php');
      const resp = await page.evaluate((t) => window.Panag.api('setTheme', { theme: t }), theme);
      expect(resp.status).toBe(true);

      const pages = ['index.php', 'profile.php', 'admin/users.php', `admin/user.php?id=${admin.id}`, 'admin/networks.php', 'admin/matrix.php',
        'admin/alerts.php', 'admin/rules.php', 'admin/logs.php', 'admin/config.php', 'admin/status.php', 'admin/monitoring.php', 'status_public.php'];
      const rules = meta.aaa ? ['color-contrast', 'color-contrast-enhanced'] : ['color-contrast'];
      const problems = [];
      const check = async (target, name) => {
        await expectTheme(target, theme);
        const shot = await target.screenshot({ fullPage: true, path: testInfo.outputPath(`${name}.png`) });
        await testInfo.attach(`${theme}-${name}`, { body: shot, contentType: 'image/png' });
        const result = await new AxeBuilder({ page: target }).withRules(rules).analyze();
        for (const v of result.violations) {
          for (const node of v.nodes) problems.push(`${name}: ${v.id} ${node.target.join(' ')} – ${node.failureSummary.split('\n').pop().trim()}`);
        }
        // axe files text in exactly its background colour as "incomplete" (equalRatio), not as a violation.
        for (const v of result.incomplete) {
          for (const node of v.nodes) {
            if (node.any.some((c) => c.data && (c.data.messageKey === 'equalRatio' || c.data.contrastRatio === 1))) {
              problems.push(`${name}: ${v.id} ${node.target.join(' ')} – invisible text (1:1)`);
            }
          }
        }
      };
      for (const path of pages) {
        await page.goto(`/${path}`);
        await page.waitForLoadState('networkidle');
        await check(page, path.replace(/[/?=]/g, '_'));
      }
      // The palette overlay and the login page (cookie) as well.
      await page.goto('/profile.php');
      await page.keyboard.press('/');
      await page.keyboard.type('o');
      await expect(page.getByTestId('palette-dialog').getByRole('option').first()).toBeVisible();
      await check(page, 'palette');
      await context.close();

      const anon = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders: { 'X-Forwarded-For': admin.ip } });
      await anon.addCookies([{ name: 'panag_theme', value: theme, url: testInfo.project.use.baseURL }]);
      const loginPage = await anon.newPage();
      await loginPage.goto('/login.php');
      await check(loginPage, 'login');
      await anon.close();

      expect(problems, `${meta.aaa ? 'WCAG AAA' : 'WCAG AA'} contrast problems in theme ${theme}`).toEqual([]);
    });
  }
});
