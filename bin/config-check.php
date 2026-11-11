<?php
// Print configuration problems (run by the container entrypoint; they also show on admin/config.php).
// Usage: php bin/config-check.php   – exit code 0 even with warnings (the app still starts).
require __DIR__ . '/_cli.php';

// Create DATA_DIR/monitor.token at container start, so the RouterOS scheduler can read it right away.
if (MONITOR_ENABLED) {
    monitor_token();
}

foreach (panag_config_warnings() as $warning) {
    fwrite(STDERR, 'CONFIG WARNING ' . $warning['name'] . ': ' . $warning['message'] . PHP_EOL);
}
