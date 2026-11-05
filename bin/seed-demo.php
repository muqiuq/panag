<?php
// Insert demo users and networks (development and E2E tests only).
// Usage: php bin/seed-demo.php [--if-empty]
//
// All demo users share the OTP secret below; get the current code with `./run.sh otp`.
require __DIR__ . '/_cli.php';

const DEMO_OTP_SECRET = 'JBSWY3DPEHPK3PXP';

$opts = cli_options($argv);
$pdo = db();
if (!is_db_empty($pdo)) {
    if (!empty($opts['if-empty'])) {
        echo 'Database not empty; demo data skipped.' . PHP_EOL;
        exit(0);
    }
    cli_fail('Database is not empty; refusing to insert demo data. Use ./run.sh reset for a fresh database.');
}

// [username, user_ip, isadmin, accesslevel]
$users = [
    ['Local Tester', '127.0.0.1', 1, 12],   // default dev identity (DEV_DEFAULT_IP) and E2E admin
    ['Admin User', '10.0.0.1', 1, 10],
    ['Regular User', '10.0.0.2', 0, 5],
    ['Login Tester', '10.0.0.9', 0, 1],     // used only by the login E2E test (OTP codes are single-use)
];
foreach ($users as [$name, $ip, $isAdmin, $level]) {
    save_user(null, $name, $ip, DEMO_OTP_SECRET, $isAdmin, $level);
}

// [name, accesslevel, address]
$networks = [
    ['Office LAN', 1, '10.10.0.0/24'],
    ['Printers', 2, '10.10.5.0/24'],
    ['VPN', 5, '172.16.0.0/24'],
    ['Management', 7, '10.99.0.0/24'],
    ['Datacenter', 8, '192.168.100.0/24'],
    ['Core switches', 12, '10.255.0.0/28'],
];
foreach ($networks as [$name, $level, $address]) {
    save_network(null, $name, $level, $address);
}

$netIds = $pdo->query('SELECT name, id FROM networks')->fetchAll(PDO::FETCH_KEY_PAIR);
$defaults = [
    '127.0.0.1' => ['Office LAN'],
    '10.0.0.1' => ['Office LAN', 'VPN', 'Datacenter'],
    '10.0.0.2' => ['Office LAN', 'Printers'],
];
foreach ($defaults as $ip => $names) {
    $user = fetch_user_by_user_ip($ip);
    if ($user) {
        set_user_default_networks((int)$user['id'], array_map(fn($n) => $netIds[$n], $names));
    }
}

log_event('demo_data_seeded', count($users) . ' users, ' . count($networks) . ' networks');
echo 'Demo data inserted into ' . DB_PATH . PHP_EOL;
