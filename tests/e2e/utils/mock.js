// Helpers for the mock RouterOS control API (dev/mock-routeros/router.php).
const { MOCK_URL } = require('./users');

async function mockRequest(method, path, body) {
  const resp = await fetch(MOCK_URL + path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!resp.ok) throw new Error(`mock ${method} ${path} -> ${resp.status}`);
  return resp.json();
}

const resetMock = () => mockRequest('POST', '/_mock/reset');
const mockState = () => mockRequest('GET', '/_mock/state');
const setFault = (mode, latencyMs = 0) => mockRequest('POST', '/_mock/fault', { mode, latency_ms: latencyMs });

/** Create an address-list entry directly on the mock router (as if granted earlier). */
async function addRouterEntry(list, address, comment, timeout) {
  const resp = await fetch(MOCK_URL + '/rest/ip/firewall/address-list', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: 'Basic ' + Buffer.from('admin:mock').toString('base64') },
    body: JSON.stringify({ list, address, comment, timeout }),
  });
  if (!resp.ok) throw new Error(`mock PUT -> ${resp.status}`);
  return resp.json();
}

/** Seconds until the entry for address expires on the mock router (null if missing). */
async function remainingOnRouter(address) {
  const state = await mockState();
  const entry = state.entries.find((e) => e.address === address);
  return entry ? entry.expires_at - Math.floor(Date.now() / 1000) : null;
}

/** Change (or with add: true create) a WireGuard peer on the mock router. */
const setPeer = (fields) => mockRequest('POST', '/_mock/wireguard', fields);

module.exports = { resetMock, mockState, setFault, addRouterEntry, remainingOnRouter, setPeer };
