<?php
// PANAG configuration – every value is set via environment variable (RouterOS /container/envs, Compose, .env).
// For secrets, VAR_FILE=/path/to/file may be used instead of VAR (e.g. RouterOS container mounts).
// Each setting is registered with group, description and type; admin/config.php shows all of them
// (secrets never), .env.example documents them (checked by tests/unit/ConfigTest.php).
// Nothing here is stored in the database – the environment is the single source of truth.

/**
 * Read an environment value with its origin.
 * @return array{value: ?string, source: string, file: ?string} source: env | file | default
 */
function panag_env_info(string $key): array
{
    $value = getenv($key);
    if ($value !== false && $value !== '') {
        return ['value' => $value, 'source' => 'env', 'file' => null];
    }
    $file = getenv($key . '_FILE');
    if ($file !== false && $file !== '') {
        if (is_readable($file)) {
            return ['value' => rtrim((string)file_get_contents($file), "\r\n"), 'source' => 'file', 'file' => $file];
        }
        panag_config_warn($key, $key . '_FILE points to a file that cannot be read: ' . $file);
        return ['value' => null, 'source' => 'default', 'file' => $file];
    }
    return ['value' => null, 'source' => 'default', 'file' => null];
}

/**
 * Read a configuration value from the environment.
 * Precedence: VAR, then contents of the file named in VAR_FILE, then $default.
 */
function panag_env(string $key, ?string $default = null): ?string
{
    return panag_env_info($key)['value'] ?? $default;
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

/** Record a configuration problem (shown on admin/config.php and logged at container start). */
function panag_config_warn(string $name, string $message): void
{
    $GLOBALS['PANAG_CONFIG_WARNINGS'][$name . ':' . md5($message)] = ['name' => $name, 'message' => $message];
}

/**
 * Define a configuration constant and remember its metadata (admin/config.php).
 * @param mixed $value
 */
function panag_define(string $name, $value, bool $fromEnv, array $meta = []): void
{
    if (!defined($name)) {
        define($name, $value);
    }
    $GLOBALS['PANAG_CONFIG'][$name] = $meta + ['source' => $fromEnv ? 'env' : 'default', 'file' => null, 'group' => 'Other', 'description' => '', 'secret' => false, 'type' => 'string', 'default' => null];
}

/** @return array<string, array{source: string, file: ?string, group: string, description: string, secret: bool, type: string, default: mixed}> */
function panag_config_items(): array
{
    return $GLOBALS['PANAG_CONFIG'] ?? [];
}

/** @return array<string, string> name => env|file|default (kept for callers of the old API) */
function panag_config_sources(): array
{
    return array_map(fn($meta) => $meta['source'], panag_config_items());
}

/** Secrets are flagged at definition; the name pattern is a safety net for anything added later. */
function panag_config_is_secret(string $name): bool
{
    return (panag_config_items()[$name]['secret'] ?? false) || preg_match('/PASSWORD|TOKEN|SECRET|KEY/i', $name) === 1;
}

$GLOBALS['PANAG_CONFIG'] = [];
$GLOBALS['PANAG_CONFIG_WARNINGS'] = $GLOBALS['PANAG_CONFIG_WARNINGS'] ?? [];
$GLOBALS['PANAG_CONFIG_GROUP'] = 'Application';

/**
 * Register one setting. Types: string, int, bool, list, duration (seconds; input like "2h", "30m", "1:30"),
 * enum (meta "values"; an invalid value is kept and reported – the feature using it switches off).
 * @param mixed $default
 */
$cfg = static function (string $name, $default, string $type, string $description, array $meta = []): void {
    $info = panag_env_info($name);
    $raw = $info['value'];
    switch ($type) {
        case 'int':
            if ($raw !== null && !is_numeric($raw)) {
                panag_config_warn($name, $name . ' must be a number, got "' . $raw . '" – using ' . $default . '.');
            }
            $value = ($raw !== null && is_numeric($raw)) ? (int)$raw : (int)$default;
            break;
        case 'bool':
            if ($raw !== null && !in_array(strtolower(trim($raw)), ['1', 'true', 'yes', 'on', '0', 'false', 'no', 'off'], true)) {
                panag_config_warn($name, $name . ' must be true or false, got "' . $raw . '".');
            }
            $value = $raw === null ? (bool)$default : in_array(strtolower(trim($raw)), ['1', 'true', 'yes', 'on'], true);
            break;
        case 'list':
            $items = $raw === null ? false : preg_split('/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY);
            $value = $items === false ? (array)$default : $items;
            break;
        case 'duration':
            $seconds = $raw === null ? null : parse_duration_input($raw);
            if ($raw !== null && $seconds === null) {
                panag_config_warn($name, $name . ' must be a duration like 30m, 2h or 1:30, got "' . $raw . '" – using the default.');
            }
            $value = $seconds ?? (int)parse_duration_input((string)$default);
            break;
        case 'enum':
            $value = $raw === null ? $default : strtolower(trim($raw));
            if (!in_array($value, $meta['values'], true)) {
                panag_config_warn($name, $name . ' must be one of ' . implode(', ', $meta['values']) . ', got "' . $value . '".');
            }
            break;
        default:
            $value = $raw ?? $default;
    }
    panag_define($name, $value, $raw !== null, [
        'source' => $raw === null ? 'default' : $info['source'],
        'file' => $info['file'],
        'group' => $GLOBALS['PANAG_CONFIG_GROUP'],
        'description' => $description,
        'secret' => (bool)($meta['secret'] ?? false),
        'type' => $type,
        'default' => $default,
    ] + (isset($meta['values']) ? ['values' => $meta['values']] : []));
};
$group = static function (string $name): void {
    $GLOBALS['PANAG_CONFIG_GROUP'] = $name;
};

define('APP_ROOT', dirname(__DIR__));

// --- Application -------------------------------------------------------------
$group('Application');
$cfg('APP_ENV', 'production', 'string', '"dev" enables the client IP switcher and demo helpers – never in production');
$cfg('APP_NAME', 'PANAG', 'string', 'Name shown in the UI, mails and authenticator apps');
$cfg('APP_TIMEZONE', 'Europe/Zurich', 'string', 'Time zone for times in the UI and in mails');
$cfg('APP_BASE_URL', '', 'string', 'Public URL of PANAG for links in mails, e.g. https://panag.vpn.example (reachable via VPN)');
date_default_timezone_set(APP_TIMEZONE);

$__verPath = APP_ROOT . '/VERSION';
define('APP_VERSION', is_readable($__verPath) ? trim((string)file_get_contents($__verPath)) : 'dev');
unset($__verPath);

// --- Storage -----------------------------------------------------------------
$group('Storage');
$cfg('DATA_DIR', APP_ROOT . '/data', 'string', 'SQLite database, backups, GeoIP databases and runtime files (mount this)');
define('DB_PATH', rtrim(DATA_DIR, '/') . '/panag.sqlite');
define('DB_DSN', 'sqlite:' . DB_PATH);
// Creating this file clears all failed login attempts on the next login page view.
define('RESET_LOGIN_FILE', rtrim(DATA_DIR, '/') . '/reset_login_attempts.txt');

// --- MikroTik RouterOS REST API ----------------------------------------------
$group('Router');
$cfg('MIKROTIK_BASE_URL', 'http://172.17.0.1/rest', 'string', 'RouterOS REST API base URL');
$cfg('MIKROTIK_USERNAME', 'admin', 'string', 'RouterOS API user (own user with minimal policies recommended)');
$cfg('MIKROTIK_PASSWORD', '', 'string', 'Password of the RouterOS API user', ['secret' => true]);
$cfg('MIKROTIK_CERT_FINGERPRINT', '', 'string', 'SHA-256 fingerprint to pin a self-signed certificate (empty = require CA trust)');
$cfg('MIKROTIK_CONNECT_TIMEOUT', 5, 'int', 'Connect timeout to the router (seconds)');
$cfg('MIKROTIK_TIMEOUT', 15, 'int', 'Timeout for a whole router request (seconds)');
$cfg('WIREGUARD_INTERFACE', 'wg0', 'string', 'WireGuard interface whose peers are shown and monitored (empty = all)');

// --- Access grants -----------------------------------------------------------
$group('Access grants');
$cfg('ADDRESS_LIST_PREFIX', 'Whitelist ', 'string', 'Prefix of the per-user address lists ("<prefix><user ip>")');
$cfg('MAX_DEFAULT_DURATION', '14h', 'string', 'Upper limit for default access (can only lower the hard limit of 14 h)');
$cfg('MAX_EXTENDED_DURATION', '12h', 'string', 'Upper limit for single networks (can only lower the hard limit of 12 h)');
$cfg('MAX_ACCESS_LEVEL', 15, 'int', 'Highest access level for users and networks');

// --- Login & sessions --------------------------------------------------------
$group('Login');
$cfg('LOGIN_IP_WHITELIST', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.1/32'], 'list', 'Only clients in these ranges see the login form (CIDR or single IP)');
$cfg('TRUSTED_PROXIES', [], 'list', 'Reverse proxies whose X-Forwarded-For is trusted – leave empty when clients reach PANAG directly');
$cfg('DEV_DEFAULT_IP', '', 'string', 'Dev only (APP_ENV=dev): IP assumed when no dev IP cookie is set');
$cfg('SETUP_TOKEN', '', 'string', 'Optional extra secret for setup.php (only reachable while no admin exists)', ['secret' => true]);
$cfg('SESSION_LIFETIME', 9 * 60 * 60, 'int', 'Session lifetime (seconds)');
$cfg('MAX_LOGIN_ATTEMPTS_PER_HOUR', 5, 'int', 'Failed logins per hour before the login is blocked');
$cfg('LOGIN_ATTEMPT_TTL', 7 * 24 * 60 * 60, 'int', 'How long failed login attempts are kept (seconds)');
$cfg('MAX_AUDIT_LOG_ENTRIES', 10000, 'int', 'Audit log entries kept (oldest are removed)');

// --- OTP ---------------------------------------------------------------------
$group('OTP');
$cfg('OTP_STEP', 30, 'int', 'TOTP time step (seconds)');
$cfg('OTP_DIGITS', 6, 'int', 'TOTP code length');
$cfg('OTP_ISSUER', APP_NAME, 'string', 'Issuer shown in authenticator apps');

// --- Security monitoring (docs/plan-security-monitoring.md) ------------------
$group('Monitoring');
$cfg('MONITOR_ENABLED', false, 'bool', 'Master switch for security monitoring (alerts, WireGuard/GeoIP checks, mails)');
$cfg('MONITOR_TOKEN', '', 'string', 'Token the scheduler sends as X-Monitor-Token to monitor.php (empty = generated in DATA_DIR/monitor.token)', ['secret' => true]);
$cfg('MONITOR_ALLOWED_SOURCES', ['172.17.0.1/32'], 'list', 'Clients allowed to trigger monitor.php (CIDR list; normally only the router)');
$cfg('MONITOR_INTERVAL', 300, 'int', 'Seconds between cycles for bin/monitor.php --loop');
$cfg('MONITOR_ALLOWED_COUNTRIES', ['CH'], 'list', 'ISO country codes that never alert by themselves (rule W2)');
$cfg('MONITOR_LEARNING_DAYS', 14, 'int', 'Days before behaviour-based rules may alert for a user');
$cfg('MONITOR_TRAVEL_WINDOW', '2h', 'duration', 'A change to an unknown country within this time counts as rapid change (rule W3)');
$cfg('MONITOR_FAILED_LOGINS', 5, 'int', 'Failed logins of one user IP that trigger rule P1');
$cfg('MONITOR_FAILED_LOGINS_WINDOW', '15m', 'duration', 'Time window for MONITOR_FAILED_LOGINS');
$cfg('MONITOR_BUNDLE_WINDOW', '30m', 'duration', 'Findings of one user within this time become one alert');
$cfg('MONITOR_COOLDOWN', '24h', 'duration', 'The same finding (user, rule, country …) alerts at most once in this time');
$cfg('MONITOR_DIGEST_TIME', '07:00', 'string', 'Daily digest (low/info alerts) at this local time (HH:MM)');
$cfg('MONITOR_NOTIFY_USERS', true, 'bool', 'Also mail the affected user ("Was this you?") for location and OTP findings');
$cfg('MONITOR_HOSTING_ASNS', [], 'list', 'Additional AS numbers treated as hosting/VPN networks (rule W4)');
$cfg('MONITOR_IP_RETENTION_DAYS', 30, 'int', 'Public WireGuard endpoint IPs are removed after this many days (country/ASN stay)');
$cfg('MONITOR_ALERT_RETENTION_DAYS', 365, 'int', 'Alerts are deleted after this many days');
$cfg('MONITOR_PSEUDONYM_KEY', '', 'string', 'HMAC key for pseudonyms sent to the AI (empty = generated in DATA_DIR)', ['secret' => true]);

// --- GeoIP -------------------------------------------------------------------
$group('GeoIP');
$cfg('GEOIP_COUNTRY_DB', rtrim(DATA_DIR, '/') . '/geoip/country.mmdb', 'string', 'Country database (MMDB: DB-IP Lite or MaxMind GeoLite2)');
$cfg('GEOIP_ASN_DB', rtrim(DATA_DIR, '/') . '/geoip/asn.mmdb', 'string', 'ASN database (MMDB); missing file = ASN rules off');
$cfg('GEOIP_AUTO_UPDATE', true, 'bool', 'Download the DB-IP Lite databases monthly (needs internet access from the container)');

// --- Mail ----------------------------------------------------------------------
$group('Mail');
$cfg('MAIL_TRANSPORT', 'smtp', 'enum', 'How alerts are mailed: smtp or none', ['values' => ['smtp', 'none']]);
$cfg('SMTP_HOST', '', 'string', 'SMTP relay host');
$cfg('SMTP_PORT', 587, 'int', 'SMTP port (587 STARTTLS, 465 TLS)');
$cfg('SMTP_SECURITY', 'starttls', 'enum', 'starttls or tls; none only with APP_ENV=dev (local mail catcher)', ['values' => ['starttls', 'tls', 'none']]);
$cfg('SMTP_USERNAME', '', 'string', 'SMTP user (empty = no authentication)');
$cfg('SMTP_PASSWORD', '', 'string', 'SMTP password', ['secret' => true]);
$cfg('SMTP_TIMEOUT', 10, 'int', 'SMTP timeout (seconds)');
$cfg('MAIL_FROM', '', 'string', 'Sender address of alert mails');
$cfg('MAIL_FROM_NAME', 'PANAG', 'string', 'Sender name of alert mails');
$cfg('ALERT_ADMIN_EMAILS', [], 'list', 'Additional recipients of admin alerts (besides admins with an e-mail address)');

// --- AI triage (OpenRouter) ----------------------------------------------------
$group('AI');
$cfg('MONITOR_AI', 'off', 'enum', 'AI triage of alerts: off or openrouter', ['values' => ['off', 'openrouter']]);
$cfg('OPENROUTER_API_KEY', '', 'string', 'OpenRouter API key (own key for PANAG, with a spending limit)', ['secret' => true]);
$cfg('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1', 'string', 'OpenRouter API base URL (EU: https://eu.openrouter.ai/api/v1)');
$cfg('OPENROUTER_MODEL', 'z-ai/glm-5.3', 'string', 'Pinned model id (no ~aliases)');
$cfg('OPENROUTER_PROVIDERS', [], 'list', 'Allowed providers ("only"); required when AI is on – zero data retention is always enforced');
$cfg('OPENROUTER_MAX_PRICE_PROMPT', 2, 'int', 'Max. price in USD per million input tokens');
$cfg('OPENROUTER_MAX_PRICE_COMPLETION', 6, 'int', 'Max. price in USD per million output tokens');
$cfg('OPENROUTER_REASONING_EFFORT', 'low', 'enum', 'Reasoning effort: off, low, medium or high', ['values' => ['off', 'low', 'medium', 'high']]);
$cfg('MONITOR_AI_MAX_CALLS_PER_DAY', 20, 'int', 'Max. AI calls per day (then template mails)');
$cfg('MONITOR_AI_TIMEOUT', 20, 'int', 'Timeout of one AI call (seconds)');

unset($cfg, $group);
$GLOBALS['PANAG_CONFIG_GROUP'] = 'Other';

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
