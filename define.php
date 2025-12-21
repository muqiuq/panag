<?php
// Core configuration for PANAG
// Adjust values as needed for your environment.

// SQLite database location
const DB_PATH = __DIR__ . '/data/panag.sqlite';
const DB_DSN = 'sqlite:' . DB_PATH;

// Demo data population guard
const ALLOW_DEMO_DATA = true;

// Mikrotik REST API settings
const MIKROTIK_BASE_URL = 'http://172.17.0.1/rest'; // e.g., http://192.168.88.1/rest
const MIKROTIK_USERNAME = 'admin';
const MIKROTIK_PASSWORD = 'Hallo1234..x';

// Address list naming
const ADDRESS_LIST_PREFIX = 'Whitelist ';
const DEFAULT_TIMEOUT = '01:00:00';
const EXTENDED_TIMEOUT = '00:15:00';

// Session lifetime (seconds)
const SESSION_LIFETIME = 8 * 60 * 60; // 8 hours
const MAX_LOGIN_ATTEMPTS_PER_HOUR = 5;
const LOGIN_ATTEMPT_TTL = 7 * 24 * 60 * 60; // keep login attempts for 7 days
const MAX_AUDIT_LOG_ENTRIES = 10000;

// Time-based greetings (hour ranges are start inclusive, end exclusive, 24h)
const GREETING_MESSAGES = [
	['start' => 5,  'end' => 12, 'greeting' => 'Good morning',   'quip' => 'Rise and shine!'],
	['start' => 12, 'end' => 17, 'greeting' => 'Good afternoon', 'quip' => 'Let’s keep the packets flowing.'],
	['start' => 17, 'end' => 22, 'greeting' => 'Good evening',   'quip' => 'It\'s getting late, stay secure!'],
	['start' => 22, 'end' => 24, 'greeting' => 'Good night',     'quip' => 'May your connections be quiet.'],
	['start' => 0,  'end' => 5,  'greeting' => 'Good night',     'quip' => 'May your connections be quiet.'],
];

// Application naming
const APP_NAME = 'PANAG';

// OTP settings
const OTP_STEP = 30; // seconds per timestep
const OTP_DIGITS = 6;
const OTP_ISSUER = APP_NAME; // shows in authenticator apps
?>
