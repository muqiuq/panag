<?php
// PANAG configuration – every value can be set via environment variable.
// For secrets, VAR_FILE=/path/to/file may be used instead of VAR (e.g. RouterOS container mounts).
// See .env.example for a complete, documented list.

/**
 * Read a configuration value from the environment.
 * Precedence: VAR, then contents of the file named in VAR_FILE, then $default.
 */
function panag_env(string $key, ?string $default = null): ?string
{
    $value = getenv($key);
    if ($value !== false && $value !== '') {
        return $value;
    }
    $file = getenv($key . '_FILE');
    if ($file !== false && $file !== '' && is_readable($file)) {
        return rtrim((string)file_get_contents($file), "\r\n");
    }
    return $default;
}

function panag_env_bool(string $key, bool $default): bool
{
    $value = panag_env($key);
    if ($value === null) {
        return $default;
    }
    return in_array(strtolower(trim($value)), ['1', 'true', 'yes', 'on'], true);
}

function panag_env_int(string $key, int $default): int
{
    $value = panag_env($key);
    return ($value !== null && is_numeric($value)) ? (int)$value : $default;
}

/** Comma or whitespace separated list. */
function panag_env_list(string $key, array $default): array
{
    $value = panag_env($key);
    if ($value === null) {
        return $default;
    }
    $items = preg_split('/[\s,]+/', $value, -1, PREG_SPLIT_NO_EMPTY);
    return $items === false ? $default : $items;
}

/**
 * Define a configuration constant and remember where its value came from (for the admin config page).
 * @param mixed $value
 */
function panag_define(string $name, $value, bool $fromEnv): void
{
    if (!defined($name)) {
        define($name, $value);
    }
    $GLOBALS['PANAG_CONFIG_SOURCES'][$name] = $fromEnv ? 'env' : 'default';
}

function panag_config_sources(): array
{
    return $GLOBALS['PANAG_CONFIG_SOURCES'] ?? [];
}

$GLOBALS['PANAG_CONFIG_SOURCES'] = [];

/** @param mixed $default */
$cfg = static function (string $name, $default, string $type = 'string'): void {
    $raw = panag_env($name);
    $fromEnv = $raw !== null;
    switch ($type) {
        case 'int':
            $value = panag_env_int($name, (int)$default);
            break;
        case 'bool':
            $value = panag_env_bool($name, (bool)$default);
            break;
        case 'list':
            $value = panag_env_list($name, (array)$default);
            break;
        default:
            $value = $raw ?? $default;
    }
    panag_define($name, $value, $fromEnv);
};

define('APP_ROOT', dirname(__DIR__));

// --- Application -------------------------------------------------------------
$cfg('APP_ENV', 'production');            // "dev" enables the client IP switcher – never use in production
$cfg('APP_NAME', 'PANAG');
$cfg('APP_TIMEZONE', 'Europe/Zurich');
date_default_timezone_set(APP_TIMEZONE);

$__verPath = APP_ROOT . '/VERSION';
define('APP_VERSION', is_readable($__verPath) ? trim((string)file_get_contents($__verPath)) : 'dev');
unset($__verPath);

// --- Storage -----------------------------------------------------------------
$cfg('DATA_DIR', APP_ROOT . '/data');
define('DB_PATH', rtrim(DATA_DIR, '/') . '/panag.sqlite');
define('DB_DSN', 'sqlite:' . DB_PATH);
// Creating this file clears all failed login attempts on the next login page view.
define('RESET_LOGIN_FILE', rtrim(DATA_DIR, '/') . '/reset_login_attempts.txt');

// --- MikroTik RouterOS REST API ----------------------------------------------
$cfg('MIKROTIK_BASE_URL', 'http://172.17.0.1/rest');
$cfg('MIKROTIK_USERNAME', 'admin');
$cfg('MIKROTIK_PASSWORD', '');
// Optional SHA-256 fingerprint to pin a self-signed certificate (leave empty to require CA trust).
$cfg('MIKROTIK_CERT_FINGERPRINT', '');
$cfg('MIKROTIK_CONNECT_TIMEOUT', 5, 'int');   // seconds
$cfg('MIKROTIK_TIMEOUT', 15, 'int');          // seconds, whole request

// --- Access grants -----------------------------------------------------------
$cfg('ADDRESS_LIST_PREFIX', 'Whitelist ');
// Upper limits for the per-user durations. Can only be lowered: hard limits are 14 h / 12 h, minimum 15 min.
$cfg('MAX_DEFAULT_DURATION', '14h');
$cfg('MAX_EXTENDED_DURATION', '12h');
$cfg('MAX_ACCESS_LEVEL', 15, 'int');
$cfg('WIREGUARD_INTERFACE', 'wg0');

// --- Login & sessions --------------------------------------------------------
// Only clients in these ranges see the login form (CIDR or single IP).
$cfg('LOGIN_IP_WHITELIST', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.1/32'], 'list');
// Reverse proxies whose X-Forwarded-For header is trusted. Leave empty when PANAG is reached directly.
$cfg('TRUSTED_PROXIES', [], 'list');
// Dev only (APP_ENV=dev): IP used when no dev IP cookie is set.
$cfg('DEV_DEFAULT_IP', '');
// Optional extra secret required by setup.php (only reachable while no admin exists).
$cfg('SETUP_TOKEN', '');
$cfg('SESSION_LIFETIME', 9 * 60 * 60, 'int');
$cfg('MAX_LOGIN_ATTEMPTS_PER_HOUR', 5, 'int');
$cfg('LOGIN_ATTEMPT_TTL', 7 * 24 * 60 * 60, 'int');
$cfg('MAX_AUDIT_LOG_ENTRIES', 10000, 'int');

// --- OTP ---------------------------------------------------------------------
$cfg('OTP_STEP', 30, 'int');
$cfg('OTP_DIGITS', 6, 'int');
$cfg('OTP_ISSUER', APP_NAME);

unset($cfg);

// --- Presentation (not configurable via env) ---------------------------------
// Time-based greetings (hour ranges are start inclusive, end exclusive, 24h)
const GREETING_MESSAGES = [
    ['start' => 5,  'end' => 12, 'greeting' => 'Good morning',   'quip' => 'Rise and shine!'],
    ['start' => 12, 'end' => 17, 'greeting' => 'Good afternoon', 'quip' => 'Let’s keep the packets flowing.'],
    ['start' => 17, 'end' => 22, 'greeting' => 'Good evening',   'quip' => 'It\'s getting late, stay secure!'],
    ['start' => 22, 'end' => 24, 'greeting' => 'Good night',     'quip' => 'It\'s time to sleep...'],
    ['start' => 0,  'end' => 5,  'greeting' => 'Good night',     'quip' => 'Go to bed, it\'s late!'],
];

// Login hero image schedule (hour ranges start inclusive, end exclusive, 24h); files live in public/img
const LOGIN_HERO_IMAGES = [
    ['start' => 0,  'end' => 5,  'file' => 'panag-logo-night.jpg'],
    ['start' => 5,  'end' => 9,  'file' => 'panag-logo-early-morning.jpg'],
    ['start' => 9,  'end' => 12, 'file' => 'panag-logo-morning-from-9-to-11.jpg'],
    ['start' => 12, 'end' => 13, 'file' => 'panag-logo-noon.jpg'],
    ['start' => 13, 'end' => 16, 'file' => 'panag-logo-afternoon.jpg'],
    ['start' => 16, 'end' => 19, 'file' => 'panag-logo-late-afternoon.jpg'],
    ['start' => 19, 'end' => 23, 'file' => 'panag-logo-evening.jpg'],
    ['start' => 23, 'end' => 24, 'file' => 'panag-logo-midnight.jpg'],
];
