const { test, expect } = require('@playwright/test');
const fs = require('fs');
const { OTP_SECRET, testIp } = require('./utils/users');

// Backup and restore on admin/config.php#backup (users, networks, everything). The specs run one after another
// (workers: 1), so restoring a backup taken a moment before brings back the same data.

async function download(page, scope, buttonName) {
  const [dl] = await Promise.all([page.waitForEvent('download'), scope.getByRole('button', { name: buttonName }).click()]);
  const path = await dl.path();
  return { name: dl.suggestedFilename(), path, json: JSON.parse(fs.readFileSync(path, 'utf8')) };
}

const flash = (page) => page.getByTestId('config-flash');

test('the users and networks pages point to the backup on the config page', async ({ page }) => {
  await page.goto('/admin/users.php');
  await page.getByRole('link', { name: 'Config → Backup and restore' }).click();
  await expect(page).toHaveURL(/admin\/config\.php#backup$/);
  await expect(page.locator('#backup')).toContainText('Backup and restore');
  await page.goto('/admin/networks.php');
  await expect(page.getByRole('link', { name: 'Config → Backup and restore' })).toBeVisible();
});

test('export users and networks, import a user', async ({ page }, testInfo) => {
  await page.goto('/admin/config.php#backup');
  const card = page.locator('#backup');
  const users = await download(page, card, 'Export users (JSON)');
  expect(users.name).toBe('users.json');
  expect(users.json.map((u) => u.user_ip)).toContain('127.0.0.1');
  const networks = await download(page, card, 'Export networks (JSON)');
  expect(networks.name).toBe('networks.json');
  expect(networks.json[0]).toHaveProperty('sensitive');

  const file = testInfo.outputPath('import-users.json');
  fs.writeFileSync(file, JSON.stringify([{ username: `E2E Imported ${Date.now()}`, user_ip: testIp(), otp_secret: OTP_SECRET, role: 'user', accesslevel: 1 }]));
  await card.getByLabel('Users file (JSON)').setInputFiles(file);
  await card.getByRole('button', { name: 'Import users' }).click();
  await expect(flash(page)).toContainText('Imported 1 new user(s).');
});

test('full backup: download, refused restores, restore of the same file', async ({ page }, testInfo) => {
  await page.goto('/admin/config.php#backup');
  const backup = await download(page, page.locator('#backup'), 'Download full backup');
  expect(backup.name).toMatch(/^panag-backup-\d{8}-\d{4}\.json$/);
  expect(backup.json.format).toBe('panag-full-backup');
  expect(typeof backup.json.schema_version).toBe('number');
  expect(Object.keys(backup.json.tables)).toEqual(expect.arrayContaining(['users', 'networks', 'user_to_network', 'settings', 'audit_log', 'alerts']));
  expect(backup.json.tables.users.map((u) => u.user_ip)).toContain('127.0.0.1');

  const restore = page.getByTestId('restore-form');
  const confirm = restore.getByLabel('Type RESTORE to confirm');
  // without the confirmation word (bypassing the browser's own check)
  await restore.getByLabel('Full backup file (JSON)').setInputFiles(backup.path);
  await confirm.evaluate((el) => { el.removeAttribute('required'); el.removeAttribute('pattern'); });
  await restore.getByRole('button', { name: 'Restore everything' }).click();
  await expect(flash(page)).toContainText('Not restored: type RESTORE');

  // a users export is not a full backup
  const wrong = testInfo.outputPath('users.json');
  fs.writeFileSync(wrong, JSON.stringify([{ username: 'x' }]));
  await restore.getByLabel('Full backup file (JSON)').setInputFiles(wrong);
  await confirm.fill('RESTORE');
  await restore.getByRole('button', { name: 'Restore everything' }).click();
  await expect(flash(page)).toContainText('Not restored: This is not a PANAG full backup.');

  // the real thing
  await restore.getByLabel('Full backup file (JSON)').setInputFiles(backup.path);
  await confirm.fill('RESTORE');
  await restore.getByRole('button', { name: 'Restore everything' }).click();
  await expect(flash(page)).toContainText(/Restored \d+ row\(s\) in \d+ table\(s\)\. The previous data was saved as panag-\d{8}-\d{6}-before-restore\.sqlite\./);
  await page.goto('/admin/logs.php?action=full_backup_restored');
  await expect(page.locator('#auditLogTable tbody')).toContainText('Full backup restored by Local Tester');
  await page.goto('/index.php');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Local Tester');
});
