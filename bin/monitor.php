<?php
// Run the security monitor: once (default) or in a loop (Docker hosts without RouterOS scheduler).
// Usage: php bin/monitor.php [--loop] [--interval=300] [--quiet]
require __DIR__ . '/_cli.php';

$opts = cli_options($argv);
if (!MONITOR_ENABLED) {
    cli_fail('Monitoring is off (MONITOR_ENABLED=false).'); // the CLI needs no MONITOR_TOKEN
}
$interval = max(30, (int)($opts['interval'] ?? MONITOR_INTERVAL));
do {
    $stats = run_monitor_cycle();
    if (empty($opts['quiet'])) {
        echo json_encode($stats, JSON_UNESCAPED_SLASHES) . PHP_EOL;
    }
    if (!empty($opts['loop'])) {
        sleep($interval);
    }
} while (!empty($opts['loop']));
exit(($stats['status'] ?? '') === 'ok' || ($stats['status'] ?? '') === 'busy' ? 0 : 1);
