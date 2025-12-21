<?php
require_once __DIR__ . '/define.php';

function base_path(): string
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $dir = dirname($_SERVER['SCRIPT_NAME'] ?? '/');
    $dir = str_replace('\\', '/', $dir);
    $dir = rtrim($dir, '/');
    if ($dir === '' || $dir === '.') {
        $dir = '';
    }
    $cached = $dir;
    return $cached;
}

function url_for(string $path): string
{
    return base_path() . '/' . ltrim($path, '/');
}

function ensure_session(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        if (defined('SESSION_LIFETIME')) {
            ini_set('session.gc_maxlifetime', (string)SESSION_LIFETIME);
            ini_set('session.cookie_lifetime', (string)SESSION_LIFETIME);
        }
        session_start();
        if (!isset($_SESSION['started_at'])) {
            $_SESSION['started_at'] = time();
        }
    }
}

function session_expires_at(): ?int
{
    if (!defined('SESSION_LIFETIME')) {
        return null;
    }
    ensure_session();
    $start = $_SESSION['started_at'] ?? time();
    return $start + SESSION_LIFETIME;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $dir = dirname(DB_PATH);
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }
        $pdo = new PDO(DB_DSN);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        init_db($pdo);
    }
    return $pdo;
}

function init_db(PDO $pdo): void
{
    $pdo->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        otp_secret TEXT NOT NULL,
        isadmin INTEGER NOT NULL DEFAULT 0,
        accesslevel INTEGER NOT NULL DEFAULT 0
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS networks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        accesslevel INTEGER NOT NULL DEFAULT 0,
        address TEXT NOT NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS user_to_network (
        user_id INTEGER NOT NULL,
        network_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, network_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
    )');
}

function is_db_empty(PDO $pdo): bool
{
    $tables = ['users', 'networks', 'user_to_network'];
    foreach ($tables as $table) {
        $count = (int)$pdo->query("SELECT COUNT(*) FROM {$table}")->fetchColumn();
        if ($count > 0) {
            return false;
        }
    }
    return true;
}

function fetch_user_by_username(string $username): ?array
{
    $stmt = db()->prepare('SELECT * FROM users WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function fetch_user_by_id(int $id): ?array
{
    $stmt = db()->prepare('SELECT * FROM users WHERE id = :id LIMIT 1');
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function verify_otp(string $secret, string $code): bool
{
    $code = trim($code);
    if (!preg_match('/^\d{6}$/', $code)) {
        return false;
    }
    $time = time();
    for ($i = -1; $i <= 1; $i++) {
        if (totp($secret, $time + ($i * OTP_STEP)) === $code) {
            return true;
        }
    }
    return false;
}

function totp(string $base32Secret, int $time): string
{
    $secret = base32_decode($base32Secret);
    $counter = pack('N*', 0) . pack('N*', intdiv($time, OTP_STEP));
    $hash = hash_hmac('sha1', $counter, $secret, true);
    $offset = ord(substr($hash, -1)) & 0x0F;
    $slice = substr($hash, $offset, 4);
    $value = unpack('N', $slice)[1] & 0x7FFFFFFF;
    $mod = 10 ** OTP_DIGITS;
    return str_pad((string)($value % $mod), OTP_DIGITS, '0', STR_PAD_LEFT);
}

function base32_decode(string $b32): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
    $bits = '';
    $output = '';
    for ($i = 0, $len = strlen($b32); $i < $len; $i++) {
        $val = strpos($alphabet, $b32[$i]);
        if ($val === false) {
            continue;
        }
        $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
    }
    for ($j = 0, $blen = strlen($bits); $j + 8 <= $blen; $j += 8) {
        $output .= chr(bindec(substr($bits, $j, 8)));
    }
    return $output;
}

function generate_otp_secret(int $length = 32): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        $secret .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return $secret;
}

function login_user(string $username, string $otp): bool
{
    $user = fetch_user_by_username($username);
    if (!$user) {
        return false;
    }
    if (!verify_otp($user['otp_secret'], $otp)) {
        return false;
    }
    ensure_session();
    $_SESSION['user_id'] = (int)$user['id'];
    return true;
}

function logout_user(): void
{
    ensure_session();
    session_unset();
    session_destroy();
}

function current_user(): ?array
{
    ensure_session();
    if (!isset($_SESSION['user_id'])) {
        return null;
    }
    return fetch_user_by_id((int)$_SESSION['user_id']);
}

function require_login(): void
{
    if (!current_user()) {
        header('Location: ' . url_for('login.php'));
        exit;
    }
}

function require_admin(): void
{
    $user = current_user();
    if (!$user || (int)$user['isadmin'] !== 1) {
        header('Location: ' . url_for('index.php'));
        exit;
    }
}

function get_default_networks_for_user(int $userId): array
{
    $stmt = db()->prepare('SELECT n.* FROM networks n JOIN user_to_network un ON n.id = un.network_id WHERE un.user_id = :uid ORDER BY n.name');
    $stmt->execute([':uid' => $userId]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function get_user_default_network_ids(int $userId): array
{
    $stmt = db()->prepare('SELECT network_id FROM user_to_network WHERE user_id = :uid');
    $stmt->execute([':uid' => $userId]);
    return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
}

function set_user_default_networks(int $userId, array $networkIds): void
{
    $pdo = db();
    $pdo->beginTransaction();
    $pdo->prepare('DELETE FROM user_to_network WHERE user_id = :uid')->execute([':uid' => $userId]);
    $stmt = $pdo->prepare('INSERT INTO user_to_network (user_id, network_id) VALUES (:uid, :nid)');
    foreach ($networkIds as $nid) {
        $stmt->execute([':uid' => $userId, ':nid' => (int)$nid]);
    }
    $pdo->commit();
}

function get_all_networks(): array
{
    return db()->query('SELECT * FROM networks ORDER BY accesslevel, name')->fetchAll(PDO::FETCH_ASSOC);
}

function user_can_access_network(array $user, array $network): bool
{
    return (int)$user['accesslevel'] >= (int)$network['accesslevel'];
}

function mikrotik_request(string $method, string $path, ?array $body = null): array
{
    $url = rtrim(MIKROTIK_BASE_URL, '/') . '/' . ltrim($path, '/');
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
    curl_setopt($ch, CURLOPT_USERPWD, MIKROTIK_USERNAME . ':' . MIKROTIK_PASSWORD);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }
    $resp = curl_exec($ch);
    $err = curl_error($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($resp === false || $err) {
        return ['success' => false, 'data' => null, 'error' => $err ?: 'unknown error', 'status' => $status];
    }
    $data = json_decode($resp, true);
    $ok = $status >= 200 && $status < 300;
    return ['success' => $ok, 'data' => $data, 'error' => $ok ? null : ('HTTP ' . $status), 'status' => $status];
}

function address_list_name(string $username): string
{
    return ADDRESS_LIST_PREFIX . $username;
}

function get_current_address_list_entries(string $username): array
{
    $resp = mikrotik_request('GET', '/ip/firewall/address-list');
    if (!$resp['success'] || !is_array($resp['data'])) {
        return [];
    }
    $listName = address_list_name($username);
    return array_values(array_filter($resp['data'], function ($entry) use ($listName) {
        return isset($entry['list']) && $entry['list'] === $listName;
    }));
}

function get_all_address_list_entries(): array
{
    $resp = mikrotik_request('GET', '/ip/firewall/address-list');
    if (!$resp['success'] || !is_array($resp['data'])) {
        return ['success' => false, 'error' => $resp['error'] ?? 'API error', 'status' => $resp['status'] ?? null, 'data' => []];
    }
    return ['success' => true, 'data' => $resp['data']];
}

function current_accesses_by_users(array $users): array
{
    $resp = get_all_address_list_entries();
    if (!$resp['success']) {
        return ['success' => false, 'error' => $resp['error'] ?? 'API error', 'status' => $resp['status'] ?? null, 'data' => []];
    }
    $data = [];
    foreach ($users as $u) {
        if (!isset($u['username'])) {
            continue;
        }
        $listName = address_list_name($u['username']);
        $entries = array_values(array_filter($resp['data'], function ($entry) use ($listName) {
            return isset($entry['list']) && $entry['list'] === $listName;
        }));
        $data[$u['username']] = $entries;
    }
    return ['success' => true, 'data' => $data];
}

function add_address_list_entry(string $username, array $network, string $timeout = DEFAULT_TIMEOUT): array
{
    $payload = [
        'list' => address_list_name($username),
        'address' => $network['address'],
        'comment' => $network['name'] ?? 'network',
        'timeout' => $timeout,
    ];
    // Mikrotik REST expects PUT to create a single record.
    $resp = mikrotik_request('PUT', '/ip/firewall/address-list', $payload);
    $message = $resp['success'] ? 'Applied' : ($resp['error'] ?? 'Failed');
    return [
        'success' => $resp['success'],
        'status' => $resp['status'] ?? null,
        'message' => $message,
    ];
}

function apply_networks_to_user(array $user, array $networks): array
{
    $results = [];
    $existingAddresses = array_map('strval', array_column(get_current_address_list_entries($user['username']), 'address'));
    foreach ($networks as $network) {
        if (!user_can_access_network($user, $network)) {
            $results[] = ['network' => $network['name'], 'success' => false, 'message' => 'Insufficient access level'];
            continue;
        }
        if (in_array($network['address'], $existingAddresses, true)) {
            $results[] = [
                'network' => $network['name'],
                'success' => true,
                'status' => null,
                'message' => 'Already present',
            ];
            continue;
        }
        $result = add_address_list_entry($user['username'], $network, DEFAULT_TIMEOUT);
        $results[] = [
            'network' => $network['name'],
            'success' => $result['success'],
            'status' => $result['status'] ?? null,
            'message' => $result['success'] ? 'Applied' : ($result['message'] ?? 'Failed'),
        ];
    }
    return $results;
}

function save_network(?int $id, string $name, int $accesslevel, string $address): void
{
    if ($id === null) {
        $stmt = db()->prepare('INSERT INTO networks (name, accesslevel, address) VALUES (:n, :a, :addr)');
        $stmt->execute([':n' => $name, ':a' => $accesslevel, ':addr' => $address]);
    } else {
        $stmt = db()->prepare('UPDATE networks SET name = :n, accesslevel = :a, address = :addr WHERE id = :id');
        $stmt->execute([':n' => $name, ':a' => $accesslevel, ':addr' => $address, ':id' => $id]);
    }
}

function delete_network(int $id): void
{
    $stmt = db()->prepare('DELETE FROM networks WHERE id = :id');
    $stmt->execute([':id' => $id]);
}

function save_user(?int $id, string $name, string $username, string $otp_secret, int $isadmin, int $accesslevel): void
{
    if ($id === null) {
        $stmt = db()->prepare('INSERT INTO users (name, username, otp_secret, isadmin, accesslevel) VALUES (:n, :u, :o, :i, :a)');
        $stmt->execute([':n' => $name, ':u' => $username, ':o' => $otp_secret, ':i' => $isadmin, ':a' => $accesslevel]);
    } else {
        $stmt = db()->prepare('UPDATE users SET name = :n, username = :u, otp_secret = :o, isadmin = :i, accesslevel = :a WHERE id = :id');
        $stmt->execute([':n' => $name, ':u' => $username, ':o' => $otp_secret, ':i' => $isadmin, ':a' => $accesslevel, ':id' => $id]);
    }
}

function delete_user(int $id): void
{
    $stmt = db()->prepare('DELETE FROM users WHERE id = :id');
    $stmt->execute([':id' => $id]);
}
?>
