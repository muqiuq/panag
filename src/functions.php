<?php
// Core helpers. Loaded via src/bootstrap.php.

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

/**
 * Same-origin check for state-changing requests. Compares host *and* port: browsers send
 * "Origin: http://host:8080" while HTTP_HOST is "host:8080" (default ports are omitted in both).
 */
function origin_matches_host(string $origin, string $httpHost): bool
{
    $parts = parse_url($origin);
    if (!is_array($parts) || empty($parts['host']) || $httpHost === '') {
        return false;
    }
    $originHost = strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '');
    return $originHost === strtolower($httpHost);
}

function origin_allowed(): bool
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === '') {
        return true; // No origin header (likely same-origin form)
    }
    return origin_matches_host($origin, (string)($_SERVER['HTTP_HOST'] ?? ''));
}

function require_csrf_token(?string $token): void
{
    if (!origin_allowed() || !verify_csrf_token($token)) {
        http_response_code(403);
        echo 'Forbidden';
        exit;
    }
}

function login_ip_allowed(string $ip): bool
{
    // Use LOGIN_IP_WHITELIST=0.0.0.0/0 to allow every client.
    return ip_in_any_cidr($ip, LOGIN_IP_WHITELIST);
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

/** Open a connection with PANAG's per-connection settings (no migrations). */
function db_connect(?string $dsn = null): PDO
{
    $dsn = $dsn ?? DB_DSN;
    if ($dsn === DB_DSN) {
        $dir = dirname(DB_PATH);
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }
    }
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // SQLite only enforces FOREIGN KEY / ON DELETE CASCADE when enabled per connection.
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA busy_timeout = 5000');
    $pdo->exec('PRAGMA journal_mode = WAL');
    return $pdo;
}

/** Shared connection; applies pending migrations (normally already done by bin/migrate.php at start). */
function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $pdo = db_connect();
        if (schema_version($pdo) < latest_schema_version()) {
            migrate($pdo);
        }
    }
    return $pdo;
}

/** Setup is only possible while no admin exists (replaces the old setup-completed.txt flag file). */
function admin_exists(): bool
{
    return (int)db()->query("SELECT COUNT(*) FROM users WHERE role = 'admin'")->fetchColumn() > 0;
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

/** @param array<string, mixed>|null $meta structured data for monitoring rules (e.g. ['networks' => [ids]]) */
function log_event(string $action, string $details = '', ?int $userId = null, ?string $username = null, ?string $userIp = null, ?array $meta = null): void
{
    $ip = PHP_SAPI === 'cli' ? 'cli' : client_ip();
    $stmt = db()->prepare('INSERT INTO audit_log (user_id, username, user_ip, action, details, ip, created_at, meta) VALUES (:uid, :un, :uip, :a, :d, :ip, :ts, :m)');
    $stmt->execute([
        ':uid' => $userId,
        ':un' => $username,
        ':uip' => $userIp,
        ':a' => $action,
        ':d' => $details,
        ':ip' => $ip,
        ':ts' => time(),
        ':m' => $meta === null ? null : json_encode($meta),
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
    require_permission('admin');
}

/** Redirect to the dashboard unless the current user has $permission (see src/roles.php). */
function require_permission(string $permission): void
{
    $user = current_user();
    if (!$user) {
        header('Location: ' . url_for('login.php'));
        exit;
    }
    if (!can($user, $permission)) {
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
    $sensitive = array_flip(array_map('intval', db()->query('SELECT id FROM networks WHERE sensitive = 1')->fetchAll(PDO::FETCH_COLUMN) ?: []));
    $networkIds = array_values(array_filter($networkIds, fn($nid) => !isset($sensitive[(int)$nid])));
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

/** Networks within the user's access level, i.e. those the user may request or pick as own defaults. */
function eligible_networks_for_user(array $user): array
{
    return array_values(array_filter(get_all_networks(), fn($n) => user_can_access_network($user, $n)));
}

function fetch_network_by_id(int $id): ?array
{
    $stmt = db()->prepare('SELECT * FROM networks WHERE id = :id LIMIT 1');
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function is_valid_ipv4(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

/** "10.0.0.0/24" or a single host "10.0.0.5" (RouterOS accepts both in address lists). */
function is_valid_ipv4_cidr(string $value): bool
{
    if (strpos($value, '/') === false) {
        return is_valid_ipv4($value);
    }
    [$ip, $mask] = explode('/', $value, 2);
    return is_valid_ipv4($ip) && ctype_digit($mask) && (int)$mask <= 32;
}

/** @return list<string> */
function validate_network_input(string $name, string $address): array
{
    $errors = [];
    if ($name === '') {
        $errors[] = 'Name is required.';
    }
    if (!is_valid_ipv4_cidr($address)) {
        $errors[] = 'Address must be an IPv4 network (10.0.0.0/24) or host (10.0.0.5).';
    }
    return $errors;
}

function is_valid_otp_secret(string $secret): bool
{
    return (bool)preg_match('/^[A-Z2-7]{16,128}$/', $secret);
}

/**
 * Validate name and login IP of a user. $id = null for a new user.
 * @return list<string>
 */
function validate_user_account(?int $id, string $username, string $userIp): array
{
    $errors = [];
    if ($username === '') {
        $errors[] = 'Name is required.';
    }
    if (!is_valid_ipv4($userIp)) {
        $errors[] = 'User IP must be an IPv4 address.';
    } else {
        $existing = fetch_user_by_user_ip($userIp);
        if ($existing && (int)$existing['id'] !== (int)$id) {
            $errors[] = 'User IP ' . $userIp . ' is already used by ' . $existing['username'] . '.';
        }
    }
    return $errors;
}

/** Update name, IP, role and level (not the OTP secret). The level is clamped to MAX_ACCESS_LEVEL. */
function update_user_account(int $id, string $username, string $userIp, string $role, int $accesslevel): void
{
    if (!is_valid_role($role)) {
        throw new InvalidArgumentException('Invalid role: ' . $role);
    }
    $stmt = db()->prepare('UPDATE users SET username = :n, user_ip = :u, role = :r, accesslevel = :a WHERE id = :id');
    $stmt->execute([':n' => $username, ':u' => $userIp, ':r' => $role, ':a' => max(0, min($accesslevel, (int)MAX_ACCESS_LEVEL)), ':id' => $id]);
}

/** E-mail address for alert mails (empty = none) and whether alerts are mailed. @return string|null error */
function update_user_contact(int $id, string $email, bool $notify): ?string
{
    $email = trim($email);
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return 'Not a valid e-mail address.';
    }
    db()->prepare('UPDATE users SET email = :e, notify_alerts = :n WHERE id = :id')
        ->execute([':e' => $email !== '' ? strtolower($email) : null, ':n' => $notify ? 1 : 0, ':id' => $id]);
    return null;
}

function set_user_otp_secret(int $id, string $secret): void
{
    db()->prepare('UPDATE users SET otp_secret = :o WHERE id = :id')->execute([':o' => $secret, ':id' => $id]);
}

/** otpauth:// URI for authenticator apps (QR code). */
function otp_provisioning_uri(array $user): string
{
    $label = rawurlencode(OTP_ISSUER . ':' . $user['user_ip']);
    return 'otpauth://totp/' . $label . '?' . http_build_query([
        'secret' => $user['otp_secret'],
        'issuer' => OTP_ISSUER,
        'digits' => OTP_DIGITS,
        'period' => OTP_STEP,
    ], '', '&', PHP_QUERY_RFC3986);
}

/** Sortable audit log columns (query key => SQL column). Anything else falls back to newest first. */
const AUDIT_LOG_SORT_COLUMNS = [
    'time' => 'created_at',
    'action' => 'action',
    'user' => 'username',
    'user_ip' => 'user_ip',
    'details' => 'details',
    'ip' => 'ip',
];

/** @return array{key: string, dir: string, sql: string} */
function audit_log_order(?string $sort, ?string $dir): array
{
    $key = isset(AUDIT_LOG_SORT_COLUMNS[(string)$sort]) ? (string)$sort : 'time';
    $dir = strtolower((string)$dir);
    if ($dir !== 'asc' && $dir !== 'desc') {
        $dir = $key === 'time' ? 'desc' : 'asc';
    }
    $column = AUDIT_LOG_SORT_COLUMNS[$key] . ($key === 'time' ? '' : ' COLLATE NOCASE');
    $sqlDir = strtoupper($dir);
    // id as tie-breaker keeps pages stable
    return ['key' => $key, 'dir' => $dir, 'sql' => "ORDER BY {$column} {$sqlDir}, id {$sqlDir}"];
}

/** Admin acting as another user. The original admin is kept in the session. */
function start_impersonation(array $admin, array $target): void
{
    if (!can($admin, 'impersonate')) {
        throw new RuntimeException('Not allowed to impersonate');
    }
    if ((int)$admin['id'] === (int)$target['id']) {
        throw new InvalidArgumentException('Cannot impersonate yourself');
    }
    ensure_session();
    session_regenerate_id(true);
    $_SESSION['impersonator_id'] = (int)$admin['id'];
    $_SESSION['user_id'] = (int)$target['id'];
    log_event('impersonate_start', 'Acting as ' . ($target['username'] ?? '?') . ' (' . ($target['user_ip'] ?? '') . ')', (int)$admin['id'], $admin['username'] ?? null, $admin['user_ip'] ?? null);
}

/** The admin behind the current impersonation, or null. */
function impersonator(): ?array
{
    ensure_session();
    $id = $_SESSION['impersonator_id'] ?? null;
    return $id ? fetch_user_by_id((int)$id) : null;
}

/** End impersonation and return to the admin account. Returns the admin, or null if none was active. */
function stop_impersonation(): ?array
{
    $admin = impersonator();
    $target = current_user();
    unset($_SESSION['impersonator_id']);
    if (!$admin || !is_admin($admin)) {
        // The admin was deleted or demoted meanwhile – end the session entirely.
        logout_user();
        return null;
    }
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$admin['id'];
    log_event('impersonate_end', 'Stopped acting as ' . ($target['username'] ?? '?') . ' (' . ($target['user_ip'] ?? '') . ')', (int)$admin['id'], $admin['username'] ?? null, $admin['user_ip'] ?? null);
    return $admin;
}

function address_list_name(string $userIp): string
{
    return ADDRESS_LIST_PREFIX . $userIp;
}

function is_valid_address_list_name(string $listName): bool
{
    return strncmp($listName, ADDRESS_LIST_PREFIX, strlen(ADDRESS_LIST_PREFIX)) === 0;
}

/** The user's address-list entries, or null when the router could not be read (unknown ≠ none). */
function own_address_list_entries(string $userIp): ?array
{
    $listName = address_list_name($userIp);
    if (!is_valid_address_list_name($listName)) {
        return [];
    }
    $resp = router()->listAddressList($listName);
    return $resp['success'] && is_array($resp['data']) ? $resp['data'] : null;
}

function get_current_address_list_entries(string $userIp): array
{
    return own_address_list_entries($userIp) ?? [];
}

function get_all_address_list_entries(): array
{
    $resp = router()->listAddressList();
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
        $data[$u['user_ip']] = array_values(array_filter($resp['data'], fn($entry) => ($entry['list'] ?? null) === $listName));
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
    $byIp = last_logins_by_user_ip();
    foreach ($allUsers as $u) {
        $lastLogins[$u['user_ip']] = $byIp[$u['user_ip']] ?? null;
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
    $resp = router()->identity();
    $name = $resp['success'] && isset($resp['data']['name']) ? (string)$resp['data']['name'] : null;
    if ($name === null) {
        return ['success' => false, 'error' => $resp['error'] ?? 'Identity not found', 'data' => null];
    }
    return ['success' => true, 'error' => null, 'data' => ['name' => $name]];
}

function mikrotik_clock(): array
{
    $resp = router()->clock();
    $row = $resp['success'] && is_array($resp['data']) ? $resp['data'] : [];
    $data = [
        'time' => isset($row['time']) ? (string)$row['time'] : null,
        'date' => isset($row['date']) ? (string)$row['date'] : null,
        'time_zone' => isset($row['time-zone-name']) ? (string)$row['time-zone-name'] : null,
        'gmt_offset' => isset($row['gmt-offset']) ? (string)$row['gmt-offset'] : null,
    ];
    $hasTime = $data['time'] !== null || $data['date'] !== null;
    if (!$hasTime) {
        return ['success' => false, 'error' => $resp['error'] ?? 'Clock not found', 'data' => null];
    }
    return ['success' => true, 'error' => null, 'data' => $data];
}

function mikrotik_uptime(): array
{
    $resp = router()->resource();
    $uptime = $resp['success'] && isset($resp['data']['uptime']) ? (string)$resp['data']['uptime'] : null;
    if ($uptime === null) {
        return ['success' => false, 'error' => $resp['error'] ?? 'Uptime not found', 'data' => null];
    }
    return ['success' => true, 'error' => null, 'data' => ['uptime' => $uptime]];
}

function mikrotik_wireguard_peers(): array
{
    $resp = router()->wireguardPeers();
    if (!$resp['success'] || !is_array($resp['data'])) {
        return ['success' => false, 'error' => $resp['error'] ?? 'API error', 'data' => []];
    }
    $peers = $resp['data'];
    $iface = defined('WIREGUARD_INTERFACE') ? trim((string)WIREGUARD_INTERFACE) : '';
    if ($iface !== '') {
        $peers = array_values(array_filter($peers, function ($peer) use ($iface) {
            $pIface = $peer['interface'] ?? $peer['interface-name'] ?? '';
            return is_string($pIface) && trim($pIface) === $iface;
        }));
    }
    return ['success' => true, 'data' => $peers];
}

/** @return array<string, int> user_ip => timestamp of the last successful login */
function last_logins_by_user_ip(): array
{
    $stmt = db()->prepare('SELECT user_ip, MAX(created_at) FROM audit_log WHERE action = :action AND user_ip IS NOT NULL GROUP BY user_ip');
    $stmt->execute([':action' => 'login_success']);
    return array_map('intval', $stmt->fetchAll(PDO::FETCH_KEY_PAIR));
}

function remove_address_list_entries(string $userIp): array
{
    $listName = address_list_name($userIp);
    if (!is_valid_address_list_name($listName)) {
        return ['success' => false, 'message' => 'Invalid address list', 'status' => null, 'deleted' => 0, 'total' => 0];
    }
    $resp = router()->listAddressList($listName);
    if (!$resp['success'] || !is_array($resp['data'])) {
        return ['success' => false, 'message' => $resp['error'] ?? 'API error', 'status' => $resp['status'] ?? null, 'deleted' => 0, 'total' => 0];
    }
    $entries = array_values(array_filter($resp['data'], fn($entry) => isset($entry['.id'])));
    $deleted = 0;
    $errors = [];
    foreach ($entries as $entry) {
        $id = (string)$entry['.id'];
        $del = router()->removeAddressListEntry($id);
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

/**
 * Create or update a network. A sensitive network is never a default network: marking it removes it from the
 * default networks of every user.
 * @return int number of default assignments removed
 */
function save_network(?int $id, string $name, int $accesslevel, string $address, bool $sensitive = false): int
{
    $level = max(0, min($accesslevel, (int)MAX_ACCESS_LEVEL));
    $pdo = db();
    $pdo->beginTransaction();
    if ($id === null) {
        $stmt = $pdo->prepare('INSERT INTO networks (name, accesslevel, address, sensitive) VALUES (:n, :a, :addr, :s)');
        $stmt->execute([':n' => $name, ':a' => $level, ':addr' => $address, ':s' => (int)$sensitive]);
        $id = (int)$pdo->lastInsertId();
    } else {
        $stmt = $pdo->prepare('UPDATE networks SET name = :n, accesslevel = :a, address = :addr, sensitive = :s WHERE id = :id');
        $stmt->execute([':n' => $name, ':a' => $level, ':addr' => $address, ':s' => (int)$sensitive, ':id' => $id]);
    }
    $removed = 0;
    if ($sensitive) {
        $del = $pdo->prepare('DELETE FROM user_to_network WHERE network_id = :id');
        $del->execute([':id' => $id]);
        $removed = $del->rowCount();
    }
    $pdo->commit();
    return $removed;
}

function network_is_sensitive(array $network): bool
{
    return !empty($network['sensitive']);
}

/** Can $network be one of the default networks of $user? Level high enough and not sensitive. */
function network_can_be_default(array $user, array $network): bool
{
    return user_can_access_network($user, $network) && !network_is_sensitive($network);
}

function delete_network(int $id): void
{
    $stmt = db()->prepare('DELETE FROM networks WHERE id = :id');
    $stmt->execute([':id' => $id]);
}

function save_user(?int $id, string $username, string $userIp, string $otp_secret, string $role, int $accesslevel): void
{
    if (!is_valid_role($role)) {
        throw new InvalidArgumentException('Invalid role: ' . $role);
    }
    $level = max(0, min($accesslevel, (int)MAX_ACCESS_LEVEL));
    if ($id === null) {
        $stmt = db()->prepare('INSERT INTO users (username, user_ip, otp_secret, role, accesslevel) VALUES (:n, :u, :o, :r, :a)');
        $stmt->execute([':n' => $username, ':u' => $userIp, ':o' => $otp_secret, ':r' => $role, ':a' => $level]);
    } else {
        $stmt = db()->prepare('UPDATE users SET username = :n, user_ip = :u, otp_secret = :o, role = :r, accesslevel = :a WHERE id = :id');
        $stmt->execute([':n' => $username, ':u' => $userIp, ':o' => $otp_secret, ':r' => $role, ':a' => $level, ':id' => $id]);
    }
}

function delete_user(int $id): void
{
    $stmt = db()->prepare('DELETE FROM users WHERE id = :id');
    $stmt->execute([':id' => $id]);
}
