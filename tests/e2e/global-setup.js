// Runs once before all tests: wait for the stack, reset the mock router,
// and log in once per role (OTP codes are single-use, so tests reuse these sessions).
const fs = require('fs');
const path = require('path');
const { chromium, request } = require('@playwright/test');
const { login } = require('./utils/auth');
const { USERS } = require('./utils/users');
const { resetMock } = require('./utils/mock');

async function waitForApp(baseURL) {
  const api = await request.newContext({ baseURL });
  for (let i = 0; i < 60; i++) {
    try {
      const resp = await api.get('/healthz.php?deep=1');
      if (resp.ok()) return api.dispose();
    } catch (e) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`App at ${baseURL} did not become healthy`);
}

module.exports = async (config) => {
  const { baseURL } = config.projects[0].use;
  await waitForApp(baseURL);
  await resetMock();

  fs.mkdirSync(path.join(__dirname, '.auth'), { recursive: true });
  const browser = await chromium.launch();
  for (const key of ['admin', 'admin2', 'regular', 'superuser']) {
    const user = USERS[key];
    const context = await browser.newContext({ baseURL, extraHTTPHeaders: { 'X-Forwarded-For': user.ip } });
    const page = await context.newPage();
    await login(page);
    await context.storageState({ path: user.state });
    await context.close();
  }
  await browser.close();
};
