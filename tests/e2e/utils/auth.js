const { totp } = require('./totp');
const { OTP_SECRET } = require('./users');

/** Log in through the UI as the user identified by the context's X-Forwarded-For IP. */
async function login(page) {
  await page.goto('/login.php');
  await page.getByLabel('One-Time Password').fill(totp(OTP_SECRET));
  await page.getByRole('button', { name: 'Login' }).click();
  await page.waitForURL('**/index.php');
}

module.exports = { login };
