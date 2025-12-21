<?php
require_once __DIR__ . '/../lib/functions.php';

if (!defined('ALLOW_TESTS') || !ALLOW_TESTS) {
    http_response_code(403);
    echo 'Tests are disabled.';
    exit;
}

if (!ALLOW_DEMO_DATA) {
    echo 'Demo data disabled.';
    exit;
}

echo 'Using database path: ' . DB_PATH . "<br>\n";

$pdo = db();
if (!is_db_empty($pdo)) {
    echo 'Database is not empty; skipping demo data.';
    exit;
}

// Users
save_user(null, 'Admin User', '192.168.70.176', 'JBSWY3DPEHPK3PXP', 1, 10);
save_user(null, 'Regular User', '10.0.0.2', 'JBSWY3DPEHPK3PXP', 0, 5);
// Local tester used by Playwright in CI (loopback IP avoids MikroTik admin paths). Also admin-capable for admin flows.
save_user(null, 'Local Tester', '127.0.0.1', 'JBSWY3DPEHPK3PXP', 1, 12);

// Networks
save_network(null, 'Office LAN', 1, '10.10.0.0/24');
save_network(null, 'VPN', 5, '172.16.0.0/24');
save_network(null, 'Datacenter', 8, '192.168.100.0/24');

// Default mappings
$admin = fetch_user_by_user_ip('192.168.70.176');
$user = fetch_user_by_user_ip('10.0.0.2');
$local = fetch_user_by_user_ip('127.0.0.1');
$nets = db()->query('SELECT id, name FROM networks')->fetchAll(PDO::FETCH_KEY_PAIR);
if ($admin) {
    set_user_default_networks($admin['id'], array_keys($nets));
}
if ($user) {
    $firstTwo = array_slice(array_keys($nets), 0, 2);
    set_user_default_networks($user['id'], $firstTwo);
}
if ($local) {
    $first = array_slice(array_keys($nets), 0, 1);
    set_user_default_networks($local['id'], $first);
}

echo 'Demo data inserted.<br>\n';

if (file_exists(DB_PATH)) {
    echo 'DB file exists: ' . DB_PATH;
} else {
    echo 'DB file missing: ' . DB_PATH;
}
?>
