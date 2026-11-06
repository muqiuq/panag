<?php
// Create (or promote) an admin user from the command line, e.g. inside the container:
//   php bin/create-admin.php --ip=10.8.0.2 --name="Jane Doe" [--level=15] [--secret=BASE32]
// Prints the OTP secret and an otpauth:// URL for the authenticator app.
require __DIR__ . '/_cli.php';

$opts = cli_options($argv);
$ip = (string)($opts['ip'] ?? '');
$name = (string)($opts['name'] ?? '');
$level = (int)($opts['level'] ?? MAX_ACCESS_LEVEL);
$secret = strtoupper((string)($opts['secret'] ?? generate_otp_secret()));

if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $name === '') {
    cli_fail('Usage: php bin/create-admin.php --ip=<IPv4> --name=<display name> [--level=N] [--secret=BASE32]');
}
if (!preg_match('/^[A-Z2-7]{16,}$/', $secret)) {
    cli_fail('Secret must be Base32 (A-Z, 2-7), at least 16 characters.');
}

$existing = fetch_user_by_user_ip($ip);
save_user($existing ? (int)$existing['id'] : null, $name, $ip, $secret, 'admin', $level);
log_event('cli_admin_created', ($existing ? 'Promoted' : 'Created') . ' admin ' . $name, null, $name, $ip);

$label = rawurlencode(OTP_ISSUER . ':' . $ip);
echo ($existing ? 'Promoted' : 'Created') . " admin {$name} ({$ip}), level {$level}" . PHP_EOL;
echo "OTP secret: {$secret}" . PHP_EOL;
echo 'otpauth://totp/' . $label . '?secret=' . $secret . '&issuer=' . rawurlencode(OTP_ISSUER) . '&digits=' . OTP_DIGITS . '&period=' . OTP_STEP . PHP_EOL;
