<?php
// Apply pending database migrations (run by the container entrypoint on every start).
// A consistent backup is written to $DATA_DIR/backups before anything changes.
// Usage: php bin/migrate.php [--status]
require __DIR__ . '/_cli.php';

$opts = cli_options($argv);
$isNew = !file_exists(DB_PATH);
$pdo = db_connect();

$pending = pending_migrations($pdo);
if (!empty($opts['status'])) {
    echo 'Schema version ' . schema_version($pdo) . ' of ' . latest_schema_version() . PHP_EOL;
    echo $pending ? 'Pending: ' . implode(', ', $pending) . PHP_EOL : 'Up to date.' . PHP_EOL;
    exit(0);
}
if (!$pending) {
    echo 'Database up to date (schema ' . schema_version($pdo) . '): ' . DB_PATH . PHP_EOL;
    exit(0);
}
if (!$isNew) {
    $backup = backup_database($pdo, rtrim(DATA_DIR, '/') . '/backups', 'before-v' . latest_schema_version());
    echo 'Backup written: ' . $backup . PHP_EOL;
}
migrate($pdo, fn(string $msg) => print($msg . PHP_EOL));
echo 'Database ready (schema ' . schema_version($pdo) . '): ' . DB_PATH . PHP_EOL;
