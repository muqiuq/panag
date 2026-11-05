const { test, expect } = require('@playwright/test');

test.use({ storageState: { cookies: [], origins: [] } });

test('only public/ is served – database, sources and CLI are not reachable', async ({ request }) => {
  for (const path of ['/data/panag.sqlite', '/src/config.php', '/src/functions.php', '/bin/otp.php', '/VERSION', '/composer.json']) {
    const resp = await request.get(path);
    expect(resp.status(), path).toBe(404);
  }
  // dotfiles are explicitly denied
  expect((await request.get('/.env')).status()).toBe(403);
  expect((await request.get('/.htaccess')).status()).toBe(403);
});

test('health endpoint reports database and router', async ({ request }) => {
  const resp = await request.get('/healthz.php?deep=1');
  expect(resp.ok()).toBeTruthy();
  expect(await resp.json()).toMatchObject({ status: 'ok', db: 'ok', router: 'ok' });
});

test('API requires a session', async ({ request }) => {
  const resp = await request.get('/api.php?f=currentAccess');
  expect(resp.status()).toBe(401);
});

test('security headers are set', async ({ request }) => {
  const resp = await request.get('/login.php');
  expect(resp.headers()['x-frame-options']).toBe('DENY');
  expect(resp.headers()['x-content-type-options']).toBe('nosniff');
  expect(resp.headers()['server']).toBe('Apache');
});
