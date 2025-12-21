<?php
require_once __DIR__ . '/define.php';
require_once __DIR__ . '/mock_mikrotik.php';

function base_path(): string
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $dir = dirname($_SERVER['SCRIPT_NAME'] ?? '/');
    $dir = str_replace('\\', '/', $dir);
    if (basename($dir) === 'admin') {
        $dir = dirname($dir);
    }
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

function csrf_token(): string
{
    ensure_session();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token(?string $token): bool
{
    if (!$token) {
        return false;
    }
    ensure_session();
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function origin_allowed(): bool
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === '') {
        return true; // No origin header (likely same-origin form)
    }
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $originHost = parse_url($origin, PHP_URL_HOST) ?: '';
    return $host !== '' && strtolower($originHost) === strtolower($host);
}

function require_csrf_token(?string $token): void
{
    if (!origin_allowed() || !verify_csrf_token($token)) {
        http_response_code(403);
        echo 'Forbidden';
        exit;
    }
}

function ip_in_cidr(string $ip, string $cidr): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }
    [$subnet, $mask] = explode('/', $cidr, 2);
    if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }
    $mask = (int)$mask;
    if ($mask < 0 || $mask > 32) {
        return false;
    }
    $ipBin = inet_pton($ip);
    $subnetBin = inet_pton($subnet);
    if ($ipBin === false || $subnetBin === false) {
        return false;
    }

    // Build binary mask without integer bit shifts to avoid float conversions.
    $fullBytes = intdiv($mask, 8);
    $remainingBits = $mask % 8;
    $maskBin = str_repeat("\xFF", $fullBytes);
    if ($remainingBits > 0) {
        $maskBin .= chr((0xFF << (8 - $remainingBits)) & 0xFF);
    }
    $maskBin = str_pad($maskBin, 4, "\x00");

    return ($ipBin & $maskBin) === ($subnetBin & $maskBin);
}

function login_ip_allowed(string $ip): bool
{
    if (!defined('LOGIN_IP_WHITELIST') || !is_array(LOGIN_IP_WHITELIST)) {
        return true;
    }
    foreach (LOGIN_IP_WHITELIST as $cidr) {
        if (ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
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
        username TEXT NOT NULL,
        user_ip TEXT NOT NULL UNIQUE,
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

    $pdo->exec('CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip TEXT NOT NULL,
        success INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        user_ip TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip TEXT,
        created_at INTEGER NOT NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS otp_used (
        user_id INTEGER NOT NULL,
        otp_counter INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, otp_counter),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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

function fetch_user_by_user_ip(string $userIp): ?array
{
    $stmt = db()->prepare('SELECT * FROM users WHERE user_ip = :u LIMIT 1');
    $stmt->execute([':u' => $userIp]);
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

function verify_otp_with_counter(string $secret, string $code): array
{
    $code = trim($code);
    if (!preg_match('/^\d{6}$/', $code)) {
        return [false, null];
    }
    $time = time();
    for ($i = -1; $i <= 1; $i++) {
        $counter = intdiv($time + ($i * OTP_STEP), OTP_STEP);
        if (totp($secret, $time + ($i * OTP_STEP)) === $code) {
            return [true, $counter];
        }
    }
    return [false, null];
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

function log_login_attempt(string $userIp, string $ip, bool $success): void
{
    prune_login_attempts();
    $stmt = db()->prepare('INSERT INTO login_attempts (username, ip, success, created_at) VALUES (:u, :ip, :s, :ts)');
    $stmt->execute([
        ':u' => $userIp,
        ':ip' => $ip,
        ':s' => $success ? 1 : 0,
        ':ts' => time(),
    ]);
    if (!$success) {
        log_event('login_failed', 'Wrong OTP or user not found', null, null, $userIp);
    }
}

function otp_counter_used(int $userId, int $counter): bool
{
    $stmt = db()->prepare('SELECT 1 FROM otp_used WHERE user_id = :uid AND otp_counter = :ctr LIMIT 1');
    $stmt->execute([':uid' => $userId, ':ctr' => $counter]);
    return (bool)$stmt->fetchColumn();
}

function mark_otp_counter_used(int $userId, int $counter): void
{
    prune_otp_counters();
    $stmt = db()->prepare('INSERT OR IGNORE INTO otp_used (user_id, otp_counter, created_at) VALUES (:uid, :ctr, :ts)');
    $stmt->execute([':uid' => $userId, ':ctr' => $counter, ':ts' => time()]);
}

function prune_otp_counters(): void
{
    // Keep only recent counters (~10 minutes worth) to prevent unbounded growth.
    $cutoff = time() - (OTP_STEP * 20);
    db()->prepare('DELETE FROM otp_used WHERE created_at < :cutoff')->execute([':cutoff' => $cutoff]);
}

function prune_login_attempts(): void
{
    $cutoff = time() - (int)LOGIN_ATTEMPT_TTL;
    db()->prepare('DELETE FROM login_attempts WHERE created_at < :cutoff')->execute([':cutoff' => $cutoff]);
}

function prune_audit_log(): void
{
    $limit = (int)MAX_AUDIT_LOG_ENTRIES;
    $count = (int)db()->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();
    if ($count <= $limit) {
        return;
    }
    $toDelete = $count - $limit;
    $stmt = db()->prepare('DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log ORDER BY id ASC LIMIT :lim)');
    $stmt->bindValue(':lim', $toDelete, PDO::PARAM_INT);
    $stmt->execute();
}

function log_event(string $action, string $details = '', ?int $userId = null, ?string $username = null, ?string $userIp = null): void
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $stmt = db()->prepare('INSERT INTO audit_log (user_id, username, user_ip, action, details, ip, created_at) VALUES (:uid, :un, :uip, :a, :d, :ip, :ts)');
    $stmt->execute([
        ':uid' => $userId,
        ':un' => $username,
        ':uip' => $userIp,
        ':a' => $action,
        ':d' => $details,
        ':ip' => $ip,
        ':ts' => time(),
    ]);
    prune_audit_log();
}
function login_rate_limited(string $userIp, string $ip): bool
{
    $windowStart = time() - 3600; // 1 hour window
    $stmt = db()->prepare('SELECT COUNT(*) FROM login_attempts WHERE success = 0 AND created_at >= :ts AND (username = :u OR ip = :ip)');
    $stmt->execute([':ts' => $windowStart, ':u' => $userIp, ':ip' => $ip]);
    $failures = (int)$stmt->fetchColumn();
    return $failures >= (int)MAX_LOGIN_ATTEMPTS_PER_HOUR;
}

function login_user(string $userIp, string $otp, string $ip = ''): bool
{
    $user = fetch_user_by_user_ip($userIp);
    if (!$user) {
        log_login_attempt($userIp, $ip, false);
        return false;
    }
    if ($ip !== '' && login_rate_limited($userIp, $ip)) {
        log_event('login_rate_limited', 'Too many failed attempts', (int)$user['id'], $user['username'] ?? null, $user['user_ip']);
        return false;
    }
    [$otpOk, $counter] = verify_otp_with_counter($user['otp_secret'], $otp);
    if (!$otpOk) {
        log_login_attempt($userIp, $ip, false);
        return false;
    }
    if ($counter !== null && otp_counter_used((int)$user['id'], $counter)) {
        log_login_attempt($userIp, $ip, false);
        log_event('otp_reuse_blocked', 'Attempted reused OTP', (int)$user['id'], $user['username'] ?? null, $user['user_ip']);
        return false;
    }
    if ($counter !== null) {
        mark_otp_counter_used((int)$user['id'], $counter);
    }
    ensure_session();
    $_SESSION['user_id'] = (int)$user['id'];
    log_login_attempt($userIp, $ip, true);
    log_event('login_success', 'User logged in', (int)$user['id'], $user['username'] ?? null, $user['user_ip']);
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
    $allowedFingerprint = defined('MIKROTIK_CERT_FINGERPRINT') ? trim((string)MIKROTIK_CERT_FINGERPRINT) : '';
    $normalizedAllowed = $allowedFingerprint === '' ? '' : strtoupper(preg_replace('/[^A-Fa-f0-9]/', '', $allowedFingerprint));
    $isHttps = strncasecmp($url, 'https://', 8) === 0;
    $extractFingerprint = static function ($certInfo): ?string {
        if (!is_array($certInfo)) {
            return null;
        }
        foreach ($certInfo as $cert) {
            if (!empty($cert['Cert'])) {
                $fp = @openssl_x509_fingerprint($cert['Cert'], 'sha256');
                if ($fp !== false) {
                    return strtoupper($fp);
                }
            }
        }
        return null;
    };
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
    curl_setopt($ch, CURLOPT_USERPWD, MIKROTIK_USERNAME . ':' . MIKROTIK_PASSWORD);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    if ($isHttps) {
        // Always collect certificate info so we can surface fingerprints in errors.
        curl_setopt($ch, CURLOPT_CERTINFO, true);
        // If an allowed fingerprint is configured, relax hostname verification (common for self-signed with mismatched CN)
        // and rely on the fingerprint instead; otherwise keep strict verification.
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $normalizedAllowed === '' ? 2 : 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $normalizedAllowed === '');
    }
    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }
    $resp = curl_exec($ch);
    $err = curl_error($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $certInfo = $isHttps ? curl_getinfo($ch, CURLINFO_CERTINFO) : null;
    curl_close($ch);
    $certFingerprint = null;
    $ok = $resp !== false && !$err && $status >= 200 && $status < 300;
    if ($isHttps && !$ok) {
        $certFingerprint = $extractFingerprint($certInfo);
        // If HTTPS failed and we lack a fingerprint, re-probe with verification off to capture it for display only.
        if ($certFingerprint === null) {
            $probe = curl_init($url);
            curl_setopt($probe, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($probe, CURLOPT_CUSTOMREQUEST, 'HEAD');
            curl_setopt($probe, CURLOPT_USERPWD, MIKROTIK_USERNAME . ':' . MIKROTIK_PASSWORD);
            curl_setopt($probe, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($probe, CURLOPT_CERTINFO, true);
            curl_setopt($probe, CURLOPT_SSL_VERIFYHOST, $normalizedAllowed === '' ? 2 : 0);
            curl_setopt($probe, CURLOPT_SSL_VERIFYPEER, false); // allow capture even if untrusted
            curl_setopt($probe, CURLOPT_TIMEOUT, 5);
            curl_exec($probe);
            $probeInfo = curl_getinfo($probe, CURLINFO_CERTINFO);
            curl_close($probe);
            $certFingerprint = $extractFingerprint($probeInfo) ?: $certFingerprint;
        }
    }
    $normalizedActual = $certFingerprint ? strtoupper(preg_replace('/[^A-Fa-f0-9]/', '', $certFingerprint)) : '';
    // Enforce fingerprint match when configured; include fingerprint in any error message.
    if ($isHttps && $normalizedAllowed !== '' && $normalizedActual !== '' && $normalizedAllowed !== $normalizedActual) {
        $msg = 'SSL certificate fingerprint mismatch. Expected ' . $allowedFingerprint . ', got ' . $certFingerprint;
        return ['success' => false, 'data' => null, 'error' => $msg, 'status' => $status, 'fingerprint' => $certFingerprint];
    }
    if ($resp === false || $err) {
        $errorMsg = $err ?: 'unknown error';
        if ($certFingerprint) {
            $errorMsg .= ' (cert fingerprint: ' . $certFingerprint . ')';
        }
        return ['success' => false, 'data' => null, 'error' => $errorMsg, 'status' => $status, 'fingerprint' => $certFingerprint];
    }
    $data = json_decode($resp, true);
    if (!$ok && $certFingerprint) {
        return ['success' => false, 'data' => $data, 'error' => 'HTTP ' . $status . ' (cert fingerprint: ' . $certFingerprint . ')', 'status' => $status, 'fingerprint' => $certFingerprint];
    }
    return ['success' => $ok, 'data' => $data, 'error' => $ok ? null : ('HTTP ' . $status), 'status' => $status, 'fingerprint' => $certFingerprint];
}

function address_list_name(string $userIp): string
{
    return ADDRESS_LIST_PREFIX . $userIp;
}

function is_valid_address_list_name(string $listName): bool
{
    return strncmp($listName, ADDRESS_LIST_PREFIX, strlen(ADDRESS_LIST_PREFIX)) === 0;
}

function get_current_address_list_entries(string $userIp): array
{
    $listName = address_list_name($userIp);
    if (!is_valid_address_list_name($listName)) {
        return [];
    }
    if (is_mock_mikrotik()) {
        return mock_get_current_address_list_entries($listName);
    }
    $resp = mikrotik_request('GET', '/ip/firewall/address-list');
    if (!$resp['success'] || !is_array($resp['data'])) {
        return [];
    }
    return array_values(array_filter($resp['data'], function ($entry) use ($listName) {
        return isset($entry['list']) && $entry['list'] === $listName;
    }));
}

function get_all_address_list_entries(): array
{
    if (is_mock_mikrotik()) {
        return mock_get_all_address_list_entries();
    }
    $resp = mikrotik_request('GET', '/ip/firewall/address-list');
    if (!$resp['success'] || !is_array($resp['data'])) {
        return [
            'success' => false,
            'error' => $resp['error'] ?? 'API error',
            'status' => $resp['status'] ?? null,
            'data' => [],
            'fingerprint' => $resp['fingerprint'] ?? null,
        ];
    }
    $filtered = array_values(array_filter($resp['data'], function ($entry) {
        return isset($entry['list']) && is_valid_address_list_name((string)$entry['list']);
    }));
    return ['success' => true, 'data' => $filtered, 'fingerprint' => $resp['fingerprint'] ?? null];
}

function current_accesses_by_users(array $users): array
{
    $resp = get_all_address_list_entries();
    if (!$resp['success']) {
        return [
            'success' => false,
            'error' => $resp['error'] ?? 'API error',
            'status' => $resp['status'] ?? null,
            'data' => [],
            'fingerprint' => $resp['fingerprint'] ?? null,
        ];
    }
    $data = [];
    foreach ($users as $u) {
        if (!isset($u['user_ip'])) {
            continue;
        }
        $listName = address_list_name($u['user_ip']);
        $entries = array_values(array_filter($resp['data'], function ($entry) use ($listName) {
            return isset($entry['list']) && $entry['list'] === $listName;
        }));
        $data[$u['user_ip']] = $entries;
    }
    return ['success' => true, 'data' => $data, 'fingerprint' => $resp['fingerprint'] ?? null];
}

function admin_access_overview(): array
{
    $allUsers = db()->query('SELECT id, username, user_ip FROM users ORDER BY user_ip')->fetchAll(PDO::FETCH_ASSOC);
    $accessReport = current_accesses_by_users($allUsers);
    $lastLogins = [];
    $loggedInToday = [];
    $midnight = strtotime('today');
    $stmt = db()->prepare('SELECT DISTINCT COALESCE(CAST(user_id AS TEXT), username, user_ip) AS uid_key FROM audit_log WHERE action = :a AND created_at >= :ts');
    $stmt->execute([':a' => 'login_success', ':ts' => $midnight]);
    $keys = $stmt->fetchAll(PDO::FETCH_COLUMN);
    foreach ($keys as $k) {
        if ($k !== null && $k !== '') {
            $loggedInToday[$k] = true;
        }
    }
    foreach ($allUsers as $u) {
        $lastLogins[$u['user_ip']] = last_login_for_user_ip($u['user_ip']);
    }
    return [
        'allUsers' => $allUsers,
        'accessReport' => $accessReport,
        'lastLogins' => $lastLogins,
        'loggedInToday' => $loggedInToday,
    ];
}

function mikrotik_identity(): array
{
    if (is_mock_mikrotik()) {
        return mock_mikrotik_identity();
    }
    $resp = mikrotik_request('GET', '/system/identity');
    if (!$resp['success'] || empty($resp['data'])) {
        return ['success' => false, 'error' => $resp['error'] ?? 'API error', 'data' => null];
    }
    // RouterOS REST may return an array of objects or a single object.
    if (is_array($resp['data']) && array_keys($resp['data']) === array_filter(array_keys($resp['data']), 'is_string')) {
        $row = $resp['data'];
    } else {
        $row = is_array($resp['data']) ? reset($resp['data']) : null;
    }
    $name = is_array($row) && isset($row['name']) ? (string)$row['name'] : null;
    return ['success' => $name !== null, 'error' => $name !== null ? null : 'Identity not found', 'data' => ['name' => $name]];
}

function mikrotik_uptime(): array
{
    if (is_mock_mikrotik()) {
        return mock_mikrotik_uptime();
    }
    $resp = mikrotik_request('GET', '/system/resource');
    if (!$resp['success'] || empty($resp['data'])) {
        return ['success' => false, 'error' => $resp['error'] ?? 'API error', 'data' => null];
    }
    if (is_array($resp['data']) && array_keys($resp['data']) === array_filter(array_keys($resp['data']), 'is_string')) {
        $row = $resp['data'];
    } else {
        $row = is_array($resp['data']) ? reset($resp['data']) : null;
    }
    $uptime = is_array($row) && isset($row['uptime']) ? (string)$row['uptime'] : null;
    return ['success' => $uptime !== null, 'error' => $uptime !== null ? null : 'Uptime not found', 'data' => ['uptime' => $uptime]];
}

function mikrotik_wireguard_peers(): array
{
    if (is_mock_mikrotik()) {
        return mock_mikrotik_wireguard_peers();
    }
    $resp = mikrotik_request('GET', '/interface/wireguard/peers');
    if (!$resp['success'] || !is_array($resp['data'])) {
        return ['success' => false, 'error' => $resp['error'] ?? 'API error', 'data' => []];
    }
    return ['success' => true, 'data' => $resp['data']];
}

function last_login_for_user_ip(string $userIp): ?int
{
    $stmt = db()->prepare('SELECT created_at FROM audit_log WHERE action = :action AND user_ip = :uip ORDER BY id DESC LIMIT 1');
    $stmt->execute([':action' => 'login_success', ':uip' => $userIp]);
    $val = $stmt->fetchColumn();
    return $val !== false ? (int)$val : null;
}

function add_address_list_entry(string $userIp, array $network, string $timeout = DEFAULT_TIMEOUT): array
{
    $listName = address_list_name($userIp);
    if (!is_valid_address_list_name($listName)) {
        return ['success' => false, 'status' => null, 'message' => 'Invalid address list'];
    }
    if (is_mock_mikrotik()) {
        return mock_add_address_list_entry($listName, $network, $timeout);
    }
    $payload = [
        'list' => $listName,
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

function remove_address_list_entries(string $userIp): array
{
    $listName = address_list_name($userIp);
    if (!is_valid_address_list_name($listName)) {
        return ['success' => false, 'message' => 'Invalid address list', 'status' => null, 'deleted' => 0, 'total' => 0];
    }
    if (is_mock_mikrotik()) {
        return mock_remove_address_list_entries($listName);
    }
    $resp = mikrotik_request('GET', '/ip/firewall/address-list');
    if (!$resp['success'] || !is_array($resp['data'])) {
        return ['success' => false, 'message' => $resp['error'] ?? 'API error', 'status' => $resp['status'] ?? null, 'deleted' => 0, 'total' => 0];
    }
    $entries = array_values(array_filter($resp['data'], function ($entry) use ($listName) {
        return isset($entry['list']) && $entry['list'] === $listName && isset($entry['.id']);
    }));
    $deleted = 0;
    $errors = [];
    foreach ($entries as $entry) {
        $id = $entry['.id'];
        $del = mikrotik_request('DELETE', '/ip/firewall/address-list/' . $id);
        if ($del['success']) {
            $deleted++;
        } else {
            $errors[] = $del['error'] ?? ('Delete failed for ' . $id);
        }
    }
    return [
        'success' => empty($errors),
        'message' => empty($errors) ? 'Entries removed.' : implode('; ', array_unique($errors)),
        'deleted' => $deleted,
        'total' => count($entries),
        'errors' => $errors,
    ];
}

function apply_networks_to_user(array $user, array $networks, string $timeout = DEFAULT_TIMEOUT): array
{
    $results = [];
    $existingAddresses = array_map('strval', array_column(get_current_address_list_entries($user['user_ip']), 'address'));
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
        $result = add_address_list_entry($user['user_ip'], $network, $timeout);
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
    $level = max(0, min($accesslevel, (int)MAX_ACCESS_LEVEL));
    if ($id === null) {
        $stmt = db()->prepare('INSERT INTO networks (name, accesslevel, address) VALUES (:n, :a, :addr)');
        $stmt->execute([':n' => $name, ':a' => $level, ':addr' => $address]);
    } else {
        $stmt = db()->prepare('UPDATE networks SET name = :n, accesslevel = :a, address = :addr WHERE id = :id');
        $stmt->execute([':n' => $name, ':a' => $level, ':addr' => $address, ':id' => $id]);
    }
}

function delete_network(int $id): void
{
    $stmt = db()->prepare('DELETE FROM networks WHERE id = :id');
    $stmt->execute([':id' => $id]);
}

function save_user(?int $id, string $username, string $userIp, string $otp_secret, int $isadmin, int $accesslevel): void
{
    $level = max(0, min($accesslevel, (int)MAX_ACCESS_LEVEL));
    if ($id === null) {
        $stmt = db()->prepare('INSERT INTO users (username, user_ip, otp_secret, isadmin, accesslevel) VALUES (:n, :u, :o, :i, :a)');
        $stmt->execute([':n' => $username, ':u' => $userIp, ':o' => $otp_secret, ':i' => $isadmin, ':a' => $level]);
    } else {
        $stmt = db()->prepare('UPDATE users SET username = :n, user_ip = :u, otp_secret = :o, isadmin = :i, accesslevel = :a WHERE id = :id');
        $stmt->execute([':n' => $username, ':u' => $userIp, ':o' => $otp_secret, ':i' => $isadmin, ':a' => $level, ':id' => $id]);
    }
}

function delete_user(int $id): void
{
    $stmt = db()->prepare('DELETE FROM users WHERE id = :id');
    $stmt->execute([':id' => $id]);
}
