const { totp } = require('./totp');

async function loginAsLocalAdmin(page) {
  await page.goto('/login.php');
  await page.getByLabel('One-Time Password').fill(totp('JBSWY3DPEHPK3PXP'));
  await page.getByRole('button', { name: 'Login' }).click();
  await page.waitForURL('**/index.php');
}

module.exports = { loginAsLocalAdmin };
