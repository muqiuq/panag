const { test, expect } = require('@playwright/test');
const { resetMock, addRouterEntry } = require('./utils/mock');
const { as } = require('./utils/ui');

// --- reference implementation of the expected order (independent of public/js/table-sort.js) ---

function sortKey(type, value) {
  if (value === '') return null;
  if (type === 'number') {
    const m = value.replace(/'/g, '').match(/-?\d+(?:\.\d+)?/);
    return m ? Number(m[0]) : null;
  }
  if (type === 'ip') {
    const m = value.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?/);
    return m ? [...m.slice(1, 5).map(Number), m[5] === undefined ? 32 : Number(m[5])] : null;
  }
  return value;
}

function compare(type, a, b) {
  if (type === 'number') return a - b;
  if (type === 'ip') return a.reduce((acc, part, i) => acc || part - b[i], 0);
  return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
}

function sortedProblem(type, values, dir) {
  const keys = values.map((v) => sortKey(type, v));
  const firstEmpty = keys.indexOf(null);
  if (firstEmpty !== -1 && keys.slice(firstEmpty).some((k) => k !== null)) return `empty values must come last: ${JSON.stringify(values)}`;
  const present = keys.filter((k) => k !== null);
  for (let i = 1; i < present.length; i++) {
    const c = compare(type, present[i - 1], present[i]);
    if (dir === 'asc' ? c > 0 : c < 0) return `not ${dir}: ${JSON.stringify(values)}`;
  }
  return null;
}

/** Sort keys of a column in DOM order (data-sort-value or text), without "No entries" rows. */
function columnValues(table, index) {
  return table.evaluate((t, i) => Array.from(t.tBodies[0].rows)
    .filter((r) => !r.querySelector('[colspan]'))
    .map((r) => {
      const cell = r.cells[i];
      return (cell.dataset.sortValue !== undefined ? cell.dataset.sortValue : cell.textContent).trim();
    }), index);
}

/** Click every sortable header twice (ascending, descending) and verify order and aria-sort. */
async function checkAllColumns(page, selector) {
  const table = page.locator(selector);
  await expect(table).toBeVisible();
  expect(await table.locator('tbody tr').count(), `${selector} needs rows to sort`).toBeGreaterThan(1);
  const headers = table.locator('thead tr').first().locator('th');
  let checked = 0;
  for (let i = 0; i < await headers.count(); i++) {
    const th = headers.nth(i);
    const button = th.locator('.sort-btn');
    if (await button.count() === 0) continue;
    const type = (await th.getAttribute('data-sort')) || 'text';
    const index = await th.evaluate((el) => el.cellIndex);
    for (const dir of ['asc', 'desc']) {
      await button.click();
      await expect(th).toHaveAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
      expect(sortedProblem(type, await columnValues(table, index), dir), `${selector} column "${(await th.textContent()).trim()}"`).toBeNull();
    }
    checked++;
  }
  expect(checked, `${selector} has sortable columns`).toBeGreaterThan(0);
}

const ADMIN_TABLES = [
  ['/index.php', ['#networksTable', '#activeAccessTable', '#usersOverviewTable']],
  ['/profile.php', ['#dn-1-table']],
  ['/admin/users.php', ['#usersTable']],
  ['/admin/user.php?id=3#networks', ['#dn-3-table']],
  ['/admin/networks.php', ['#networksAdminTable']],
  ['/admin/matrix.php', ['#matrixTable']],
  ['/admin/config.php', ['#configTable']],
  ['/admin/status.php', ['#usersOverviewTable', '#wireguardPeersTable']],
];

test.beforeEach(async () => {
  await resetMock();
  // Rows for the active access table and the users overview.
  await addRouterEntry('Whitelist 127.0.0.1', '10.99.0.0/24', 'PANAG ext: Management', '00:20:00');
  await addRouterEntry('Whitelist 127.0.0.1', '10.10.0.0/24', 'PANAG default: Office LAN', '02:00:00');
  await addRouterEntry('Whitelist 10.0.0.2', '10.10.0.0/24', 'PANAG default: Office LAN', '01:00:00');
});

for (const [path, tables] of ADMIN_TABLES) {
  test(`every column sorts: ${path}`, async ({ page }) => {
    await page.goto(path);
    for (const selector of tables) await checkAllColumns(page, selector);
  });
}

test.describe('regular user', () => {
  test.use(as('regular'));

  test('every column sorts: /status_public.php', async ({ page }) => {
    await page.goto('/status_public.php');
    await checkAllColumns(page, '#publicStatusTable');
  });
});

test('IP addresses and levels sort numerically', async ({ page }) => {
  await page.goto('/admin/networks.php');
  const table = page.locator('#networksAdminTable');
  await table.getByRole('button', { name: 'Address' }).click();
  const addresses = await columnValues(table, 1);
  // Text order would put 10.255.x before 10.99.x.
  expect(addresses.indexOf('10.10.5.0/24')).toBeLessThan(addresses.indexOf('10.99.0.0/24'));
  expect(addresses.indexOf('10.99.0.0/24')).toBeLessThan(addresses.indexOf('10.255.0.0/28'));
  expect(addresses.indexOf('10.255.0.0/28')).toBeLessThan(addresses.indexOf('172.16.0.0/24'));

  await table.getByRole('button', { name: 'Level' }).click();
  const levels = (await table.locator('tbody tr td:nth-child(3)').allTextContents()).map((t) => t.trim());
  expect(levels.indexOf('L8')).toBeLessThan(levels.indexOf('L12'));
});

test('keyboard sorting, remembered per table after a reload', async ({ page }) => {
  await page.goto('/index.php');
  const table = page.locator('#networksTable');
  const address = table.locator('thead th').nth(1);
  await address.locator('.sort-btn').focus();
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await expect(address).toHaveAttribute('aria-sort', 'descending');
  await page.reload();
  await expect(table.locator('thead th').nth(1)).toHaveAttribute('aria-sort', 'descending');
  await expect(table.locator('tbody tr').first()).toContainText('192.168.100.0/24');
});

test('table filter', async ({ page }) => {
  await page.goto('/index.php');
  await page.getByLabel('Filter networks').fill('printer');
  await expect(page.locator('#networksTable tbody tr:visible')).toHaveCount(1);
  await expect(page.locator('#networksTable tbody tr:visible')).toContainText('10.10.5.0/24');
});

test('audit log sorts on the server', async ({ page }) => {
  await page.goto('/admin/logs.php');
  const table = page.locator('#auditLogTable');
  await expect(table.locator('thead th').first()).toHaveAttribute('aria-sort', 'descending'); // newest first

  await table.getByRole('link', { name: 'Action' }).click();
  await expect(page).toHaveURL(/sort=action&dir=asc/);
  await expect(table.locator('thead th').nth(1)).toHaveAttribute('aria-sort', 'ascending');
  const asc = (await table.locator('tbody tr td:nth-child(2)').allTextContents()).map((t) => t.trim().toLowerCase());
  expect(asc).toEqual([...asc].sort());

  await table.getByRole('link', { name: 'Action' }).click();
  await expect(page).toHaveURL(/sort=action&dir=desc/);
  const desc = (await table.locator('tbody tr td:nth-child(2)').allTextContents()).map((t) => t.trim().toLowerCase());
  expect(desc).toEqual([...desc].sort().reverse());

  // Filtering keeps the order.
  await page.locator('input[name="q"]').fill('login');
  await page.getByRole('button', { name: 'Filter' }).click();
  await expect(page).toHaveURL(/sort=action/);
  await expect(page).toHaveURL(/dir=desc/);
});
