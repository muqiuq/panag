<?php
// Print the current TOTP code for a Base32 secret (default: demo secret).
// Usage: php bin/otp.php [SECRET]
require __DIR__ . '/_cli.php';

$secret = $argv[1] ?? 'JBSWY3DPEHPK3PXP';
$now = time();
$remaining = OTP_STEP - ($now % OTP_STEP);
echo totp($secret, $now) . PHP_EOL;
fwrite(STDERR, "(valid for {$remaining}s; codes are single-use per user)" . PHP_EOL);
