// Shared helpers for the E2E specs.
const { USERS, NETWORKS } = require('./users');

/** test.use() options to act as one of the demo users (see utils/users.js). */
const as = (key) => ({ storageState: USERS[key].state, extraHTTPHeaders: { 'X-Forwarded-For': USERS[key].ip } });

/** Container of the toast notifications (Panag.toast in public/js/app.js). */
const toasts = (page) => page.getByTestId('toasts');

/** Call api.php from within the page (session cookie + CSRF token of the page). */
async function callApi(page, action, body) {
  return page.evaluate(async ({ action: f, body: payload }) => {
    const token = document.querySelector('meta[name="csrf-token"]').content;
    const base = document.body.dataset.basePath || '';
    const resp = await fetch(`${base}/api.php?f=${f}`, payload === undefined ? {} : {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: JSON.stringify(payload),
    });
    return { status: resp.status, body: await resp.json().catch(() => null) };
  }, { action, body });
}

/** Replace the default networks of a user via the API (the page must belong to an admin). */
async function setDefaults(page, userId, networkIds) {
  const all = Object.values(NETWORKS);
  await callApi(page, 'setDefaultNetworks', { user_id: userId, network_ids: all, enabled: false });
  if (networkIds.length) await callApi(page, 'setDefaultNetworks', { user_id: userId, network_ids: networkIds, enabled: true });
}

module.exports = { as, toasts, callApi, setDefaults };
