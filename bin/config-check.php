<?php
// Print configuration problems (run by the container entrypoint; they also show on admin/config.php).
// Usage: php bin/config-check.php   – exit code 0 even with warnings (the app still starts).
require __DIR__ . '/_cli.php';

foreach (panag_config_warnings() as $warning) {
    fwrite(STDERR, 'CONFIG WARNING ' . $warning['name'] . ': ' . $warning['message'] . PHP_EOL);
}
