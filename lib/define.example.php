<?php
// Core configuration for PANAG
// Adjust values as needed for your environment.

// Application timezone (override with APP_TIMEZONE env var)
$__appTz = getenv('APP_TIMEZONE') ?: 'Europe/Zurich';
date_default_timezone_set($__appTz);

// SQLite database location (root-level data folder, not under lib)
define('DB_PATH', dirname(__DIR__) . '/data/panag.sqlite');
define('DB_DSN', 'sqlite:' . DB_PATH);
define('SETUP_FLAG_PATH', dirname(__DIR__) . '/setup-completed.txt');
define('RESET_LOGIN_FILE', dirname(__DIR__) . '/reset_login_attempts.txt');

// Demo data population guard
const ALLOW_DEMO_DATA = false;

// Test utilities guard
const ALLOW_TESTS = false;

// Mikrotik REST API settings
const MIKROTIK_BASE_URL = 'http://172.17.0.1/rest'; // e.g., http://192.168.88.1/rest
const MIKROTIK_USERNAME = 'admin';
const MIKROTIK_PASSWORD = '1234';
// Optional SHA-256 fingerprint to allow a specific self-signed certificate (leave empty to require CA trust)
const MIKROTIK_CERT_FINGERPRINT = '780C66AEE1DD618057B036232B92975BAF221D6CE8DC81DEEDAD1115D549814F';

// Address list naming
const ADDRESS_LIST_PREFIX = 'Whitelist ';
const DEFAULT_TIMEOUT = '01:00:00';
const EXTENDED_TIMEOUT = '00:15:00';
const MAX_ACCESS_LEVEL = 15;

// WireGuard interface to display peers for
const WIREGUARD_INTERFACE = 'wg0';

// Login IP whitelist (CIDR or single IP). Only clients in these ranges see the login form.
const LOGIN_IP_WHITELIST = [
	'10.0.0.0/8',
	'172.16.0.0/12',
	'192.168.0.0/16',
	'127.0.0.1/32',
];

// Session lifetime (seconds)
const SESSION_LIFETIME = 9 * 60 * 60; // 9 hours
const MAX_LOGIN_ATTEMPTS_PER_HOUR = 5;
const LOGIN_ATTEMPT_TTL = 7 * 24 * 60 * 60; // keep login attempts for 7 days
const MAX_AUDIT_LOG_ENTRIES = 10000;

// Time-based greetings (hour ranges are start inclusive, end exclusive, 24h)
const GREETING_MESSAGES = [
	['start' => 5,  'end' => 12, 'greeting' => 'Good morning',   'quip' => 'Rise and shine!'],
	['start' => 12, 'end' => 17, 'greeting' => 'Good afternoon', 'quip' => 'Let’s keep the packets flowing.'],
	['start' => 17, 'end' => 22, 'greeting' => 'Good evening',   'quip' => 'It\'s getting late, stay secure!'],
	['start' => 22, 'end' => 24, 'greeting' => 'Good night',     'quip' => 'It\'s time to sleep...'],
	['start' => 0,  'end' => 5,  'greeting' => 'Good night',     'quip' => 'Go to bed, it\'s late!'],
];

// Login hero image schedule (hour ranges start inclusive, end exclusive, 24h); files live in /img
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

// Application naming
const APP_NAME = 'PANAG';

// Application version (from root VERSION file, fallback to dev)
$__verPath = dirname(__DIR__) . '/VERSION';
$__appVersion = (is_readable($__verPath)) ? trim((string)file_get_contents($__verPath)) : 'dev';
define('APP_VERSION', $__appVersion);

// OTP settings
const OTP_STEP = 30; // seconds per timestep
const OTP_DIGITS = 6;
const OTP_ISSUER = APP_NAME; // shows in authenticator apps
