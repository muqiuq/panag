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

module.exports = { resetMock, mockState, setFault };
