<?php
// Semantic configuration checks. Rule: a misconfigured security-relevant feature switches itself off
// (and says why) instead of falling back to an unsafe default.

/** Why mail cannot be sent, or null when mail is ready. */
function mail_config_problem(): ?string
{
    if (MAIL_TRANSPORT === 'none') {
        return 'MAIL_TRANSPORT=none – no mails are sent.';
    }
    if (MAIL_TRANSPORT !== 'smtp') {
        return 'MAIL_TRANSPORT must be smtp or none.';
    }
    if (trim((string)SMTP_HOST) === '') {
        return 'SMTP_HOST is not set.';
    }
    if (!in_array(SMTP_SECURITY, ['starttls', 'tls', 'none'], true)) {
        return 'SMTP_SECURITY must be starttls, tls or none – mail is disabled rather than sent unencrypted.';
    }
    if (SMTP_SECURITY === 'none' && !is_dev_mode()) {
        return 'SMTP_SECURITY=none is only allowed with APP_ENV=dev.';
    }
    if (!filter_var((string)MAIL_FROM, FILTER_VALIDATE_EMAIL)) {
        return 'MAIL_FROM must be a valid e-mail address.';
    }
    return null;
}

/** Why AI triage is off, or null when it is ready. */
function ai_config_problem(): ?string
{
    if (MONITOR_AI === 'off') {
        return 'MONITOR_AI=off.';
    }
    if (MONITOR_AI !== 'openrouter') {
        return 'MONITOR_AI must be off or openrouter.';
    }
    if ((string)OPENROUTER_API_KEY === '') {
        return 'OPENROUTER_API_KEY is not set.';
    }
    if (OPENROUTER_PROVIDERS === []) {
        return 'OPENROUTER_PROVIDERS is empty – list the providers that may receive data, or set it to all.';
    }
    $model = trim((string)OPENROUTER_MODEL);
    if ($model === '' || $model[0] === '~') {
        return 'OPENROUTER_MODEL must be a pinned model id (no ~aliases).';
    }
    $url = (string)OPENROUTER_BASE_URL;
    if (strpos($url, 'https://') !== 0 && !is_dev_mode()) {
        return 'OPENROUTER_BASE_URL must use https.';
    }
    if (!in_array(OPENROUTER_REASONING_EFFORT, ['off', 'low', 'medium', 'high'], true)) {
        return 'OPENROUTER_REASONING_EFFORT must be off, low, medium or high.';
    }
    return null;
}

/** Why monitor.php refuses to run, or null. */
function monitor_config_problem(): ?string
{
    if (!MONITOR_ENABLED) {
        return 'MONITOR_ENABLED is false.';
    }
    if (monitor_token() === '') {
        return 'Cannot create ' . rtrim(DATA_DIR, '/') . '/monitor.token (DATA_DIR not writable?) – monitor.php rejects every call.';
    }
    return null;
}

/** @return list<array{name: string, message: string}> all configuration problems (parse + semantic) */
function panag_config_warnings(): array
{
    $warnings = array_values($GLOBALS['PANAG_CONFIG_WARNINGS'] ?? []);
    $add = function (string $name, string $message) use (&$warnings): void {
        $warnings[] = ['name' => $name, 'message' => $message];
    };
    foreach (MONITOR_ALLOWED_SOURCES as $cidr) {
        if (!is_valid_ipv4_cidr((string)$cidr)) {
            $add('MONITOR_ALLOWED_SOURCES', 'Not an IPv4 address or network: ' . $cidr);
        }
    }
    foreach (MONITOR_ALLOWED_COUNTRIES as $code) {
        if (!preg_match('/^[A-Z]{2}$/', (string)$code)) {
            $add('MONITOR_ALLOWED_COUNTRIES', 'Not an ISO country code (two capital letters): ' . $code);
        }
    }
    foreach (MONITOR_HOSTING_ASNS as $asn) {
        if (!ctype_digit((string)$asn)) {
            $add('MONITOR_HOSTING_ASNS', 'Not an AS number: ' . $asn);
        }
    }
    if (!preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', (string)MONITOR_DIGEST_TIME)) {
        $add('MONITOR_DIGEST_TIME', 'Must be HH:MM, got "' . MONITOR_DIGEST_TIME . '" – the daily digest is not sent.');
    }
    foreach (ALERT_ADMIN_EMAILS as $mail) {
        if (!filter_var((string)$mail, FILTER_VALIDATE_EMAIL)) {
            $add('ALERT_ADMIN_EMAILS', 'Not an e-mail address: ' . $mail);
        }
    }
    if (MONITOR_ENABLED) {
        if (($problem = monitor_config_problem()) !== null) {
            $add('MONITOR_TOKEN', $problem);
        }
        if (($problem = mail_config_problem()) !== null && MAIL_TRANSPORT !== 'none') {
            $add('MAIL_TRANSPORT', 'Alert mails are off: ' . $problem);
        }
        if (MONITOR_AI !== 'off' && ($problem = ai_config_problem()) !== null) {
            $add('MONITOR_AI', 'AI triage is off: ' . $problem);
        }
        if (!is_readable((string)GEOIP_COUNTRY_DB)) {
            $add('GEOIP_COUNTRY_DB', 'No country database at ' . GEOIP_COUNTRY_DB . ' – the location rules (W1–W3) are off until it is downloaded or uploaded (admin/monitoring.php).');
        }
        if ((string)APP_BASE_URL === '') {
            $add('APP_BASE_URL', 'Not set – alert mails contain no links to PANAG.');
        }
    }
    return $warnings;
}
