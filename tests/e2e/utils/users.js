// Demo users created by bin/seed-demo.php. All share the same OTP secret.
const OTP_SECRET = 'JBSWY3DPEHPK3PXP';

const USERS = {
  admin: { ip: '127.0.0.1', name: 'Local Tester', state: 'tests/e2e/.auth/admin.json' },
  admin2: { ip: '10.0.0.1', name: 'Admin User', state: 'tests/e2e/.auth/admin2.json' },
  regular: { ip: '10.0.0.2', name: 'Regular User', state: 'tests/e2e/.auth/regular.json' },
  superuser: { ip: '10.0.0.3', name: 'Super User', state: 'tests/e2e/.auth/superuser.json' },
  // Only used by login.spec.js – OTP codes are single-use per user and 30 s window.
  login: { ip: '10.0.0.9', name: 'Login Tester' },
};

// Database ids of the demo data (fresh database per E2E run, inserted in this order).
const USER_IDS = { admin: 1, admin2: 2, regular: 3, superuser: 4, login: 5 };
const NETWORKS = { office: 1, printers: 2, vpn: 3, management: 4, datacenter: 5, core: 6 };
// Default networks as seeded – specs that change them restore these.
const SEEDED_DEFAULTS = {
  admin: [NETWORKS.office],
  admin2: [NETWORKS.office, NETWORKS.vpn, NETWORKS.datacenter],
  regular: [NETWORKS.office, NETWORKS.printers],
  superuser: [NETWORKS.office],
};

const MOCK_URL = process.env.MOCK_URL || 'http://127.0.0.1:18081';

/**
 * Random user IP for users created by tests: 10.230–239.x.x, far from the demo data (10.0.0.x, networks
 * 10.10.x / 10.99.x / 10.255.x), so searches like "10.10" in other specs never match them.
 */
function testIp() {
  const r = (n) => Math.floor(Math.random() * n);
  return `10.${230 + r(10)}.${1 + r(250)}.${1 + r(250)}`;
}

module.exports = { OTP_SECRET, USERS, USER_IDS, NETWORKS, SEEDED_DEFAULTS, MOCK_URL, testIp };
