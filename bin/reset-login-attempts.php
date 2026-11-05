<?php
// Clear all failed login attempts (lifts the login rate limit).
require __DIR__ . '/_cli.php';

$deleted = db()->exec('DELETE FROM login_attempts');
log_event('login_attempts_reset', 'Reset via CLI (' . (int)$deleted . ' rows)');
echo 'Removed ' . (int)$deleted . ' login attempt(s).' . PHP_EOL;
