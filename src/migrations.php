<?php
// Schema migrations. The applied version is stored in SQLite's PRAGMA user_version.
// Each file src/migrations/NNN_name.php returns function (PDO $pdo): void.
// Migrations run inside a transaction and must be safe on databases created by PANAG V0.1
// (which have no user_version, i.e. version 0, but already contain the baseline tables).

/** @return array<int, array{name: string, file: string}> version => migration */
function available_migrations(): array
{
    $migrations = [];
    foreach (glob(__DIR__ . '/migrations/*.php') ?: [] as $file) {
        if (preg_match('/^(\d+)_([a-z0-9_]+)\.php$/', basename($file), $m)) {
            $migrations[(int)$m[1]] = ['name' => $m[2], 'file' => $file];
        }
    }
    ksort($migrations);
    return $migrations;
}

function latest_schema_version(): int
{
    $versions = array_keys(available_migrations());
    return $versions ? max($versions) : 0;
}

function schema_version(PDO $pdo): int
{
    return (int)$pdo->query('PRAGMA user_version')->fetchColumn();
}

/** @return list<string> migrations still to apply ("002_roles_prefs") */
function pending_migrations(PDO $pdo): array
{
    $current = schema_version($pdo);
    $pending = [];
    foreach (available_migrations() as $version => $m) {
        if ($version > $current) {
            $pending[] = sprintf('%03d_%s', $version, $m['name']);
        }
    }
    return $pending;
}

/**
 * Apply all pending migrations. Concurrent callers are serialised by BEGIN IMMEDIATE.
 * @return list<string> applied migrations
 */
function migrate(PDO $pdo, ?callable $log = null): array
{
    $applied = [];
    foreach (available_migrations() as $version => $m) {
        if ($version <= schema_version($pdo)) {
            continue;
        }
        $pdo->exec('BEGIN IMMEDIATE');
        try {
            // Re-check inside the lock: another process may have migrated meanwhile.
            if ($version > schema_version($pdo)) {
                $fn = require $m['file'];
                $fn($pdo);
                $pdo->exec('PRAGMA user_version = ' . (int)$version);
                $applied[] = sprintf('%03d_%s', $version, $m['name']);
                if ($log) {
                    $log(sprintf('Applied migration %03d_%s', $version, $m['name']));
                }
            }
            $pdo->exec('COMMIT');
        } catch (Throwable $e) {
            $pdo->exec('ROLLBACK');
            throw new RuntimeException(sprintf('Migration %03d_%s failed: %s', $version, $m['name'], $e->getMessage()), 0, $e);
        }
    }
    return $applied;
}

/**
 * Consistent copy of the database (works with WAL) into $dir; keeps the newest $keep backups.
 */
function backup_database(PDO $pdo, string $dir, string $label, int $keep = 5): string
{
    if (!is_dir($dir) && !mkdir($dir, 0770, true) && !is_dir($dir)) {
        throw new RuntimeException('Cannot create backup directory ' . $dir);
    }
    $target = sprintf('%s/panag-%s-%s.sqlite', rtrim($dir, '/'), date('Ymd-His'), preg_replace('/[^a-z0-9_-]/i', '', $label));
    $stmt = $pdo->prepare('VACUUM INTO :target');
    $stmt->execute([':target' => $target]);

    $backups = glob(rtrim($dir, '/') . '/panag-*.sqlite') ?: [];
    sort($backups);
    foreach (array_slice($backups, 0, max(0, count($backups) - $keep)) as $old) {
        @unlink($old);
    }
    return $target;
}
