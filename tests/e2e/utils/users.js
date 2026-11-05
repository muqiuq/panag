// Demo users created by bin/seed-demo.php. All share the same OTP secret.
const OTP_SECRET = 'JBSWY3DPEHPK3PXP';

const USERS = {
  admin: { ip: '127.0.0.1', name: 'Local Tester', state: 'tests/e2e/.auth/admin.json' },
  regular: { ip: '10.0.0.2', name: 'Regular User', state: 'tests/e2e/.auth/regular.json' },
  // Only used by login.spec.js – OTP codes are single-use per user and 30 s window.
  login: { ip: '10.0.0.9', name: 'Login Tester' },
};

const MOCK_URL = process.env.MOCK_URL || 'http://127.0.0.1:18081';

module.exports = { OTP_SECRET, USERS, MOCK_URL };
