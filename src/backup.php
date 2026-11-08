<?php
require_once __DIR__ . '/bootstrap.php';

function export_networks_json(): string
{
    $nets = get_all_networks();
    $payload = array_map(function ($n) {
        return [
            'name' => $n['name'] ?? '',
            'address' => $n['address'] ?? '',
            'accesslevel' => isset($n['accesslevel']) ? (int)$n['accesslevel'] : 0,
            'sensitive' => network_is_sensitive($n),
        ];
    }, $nets);
    return json_encode($payload, JSON_PRETTY_PRINT);
}

function import_networks_json(string $json, bool $replace = true): int
{
    $data = json_decode($json, true);
    if (!is_array($data)) {
        throw new InvalidArgumentException('Invalid JSON payload');
    }
    $clean = [];
    foreach ($data as $idx => $row) {
        if (!is_array($row)) {
            throw new InvalidArgumentException('Invalid item at index ' . $idx);
        }
        $name = trim((string)($row['name'] ?? ''));
        $address = trim((string)($row['address'] ?? ''));
        $level = isset($row['accesslevel']) ? (int)$row['accesslevel'] : 0;
        if ($name === '' || $address === '') {
            throw new InvalidArgumentException('Missing name or address at index ' . $idx);
        }
        $errors = validate_network_input($name, $address);
        if ($errors) {
            throw new InvalidArgumentException(implode(' ', $errors) . ' (index ' . $idx . ')');
        }
        if ($level < 0 || $level > (int)MAX_ACCESS_LEVEL) {
            throw new InvalidArgumentException('Invalid access level at index ' . $idx);
        }
        $clean[] = ['name' => $name, 'address' => $address, 'accesslevel' => $level, 'sensitive' => !empty($row['sensitive'])];
    }

    $pdo = db();
    $pdo->beginTransaction();
    try {
        if ($replace) {
            $pdo->exec('DELETE FROM networks');
        }
        $stmt = $pdo->prepare('INSERT INTO networks (name, accesslevel, address, sensitive) VALUES (:n, :a, :addr, :s)');
        foreach ($clean as $row) {
            $stmt->execute([
                ':n' => $row['name'],
                ':a' => $row['accesslevel'],
                ':addr' => $row['address'],
                ':s' => (int)$row['sensitive'],
            ]);
        }
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return count($clean);
}

function export_users_json(): string
{
    $rows = db()->query('SELECT username, user_ip, otp_secret, role, accesslevel, default_duration_sec, extended_duration_sec, theme FROM users ORDER BY user_ip')->fetchAll(PDO::FETCH_ASSOC);
    $payload = array_map(function ($u) {
        return [
            'username' => (string)$u['username'],
            'user_ip' => (string)$u['user_ip'],
            'otp_secret' => (string)$u['otp_secret'],
            'role' => (string)$u['role'],
            'accesslevel' => (int)$u['accesslevel'],
            'default_duration_sec' => (int)$u['default_duration_sec'],
            'extended_duration_sec' => (int)$u['extended_duration_sec'],
            'theme' => (string)$u['theme'],
        ];
    }, $rows);
    return json_encode($payload, JSON_PRETTY_PRINT);
}

/**
 * Import users from JSON. Accepts the current format and V0.1 exports ("isadmin": 0/1 instead of "role").
 * Existing user_ips are skipped, never overwritten.
 */
function import_users_json(string $json): array
{
    $data = json_decode($json, true);
    if (!is_array($data)) {
        throw new InvalidArgumentException('Invalid JSON payload');
    }
    $clean = [];
    foreach ($data as $idx => $row) {
        if (!is_array($row)) {
            throw new InvalidArgumentException('Invalid item at index ' . $idx);
        }
        $username = trim((string)($row['username'] ?? ''));
        $userIp = trim((string)($row['user_ip'] ?? ''));
        $otp = trim((string)($row['otp_secret'] ?? ''));
        $level = isset($row['accesslevel']) ? (int)$row['accesslevel'] : 0;
        if ($username === '' || $userIp === '' || $otp === '') {
            throw new InvalidArgumentException('Missing username, user_ip, or otp_secret at index ' . $idx);
        }
        if ($level < 0 || $level > (int)MAX_ACCESS_LEVEL) {
            throw new InvalidArgumentException('Invalid access level at index ' . $idx);
        }
        if (isset($row['role'])) {
            $role = (string)$row['role'];
            if (!is_valid_role($role)) {
                throw new InvalidArgumentException('Invalid role at index ' . $idx);
            }
        } else {
            $role = !empty($row['isadmin']) ? 'admin' : 'user';
        }
        $defaultDuration = (int)($row['default_duration_sec'] ?? 3600);
        $extendedDuration = (int)($row['extended_duration_sec'] ?? 900);
        if ($defaultDuration <= 0 || $extendedDuration <= 0) {
            throw new InvalidArgumentException('Invalid duration at index ' . $idx);
        }
        $clean[] = [
            'username' => $username,
            'user_ip' => $userIp,
            'otp_secret' => $otp,
            'role' => $role,
            'accesslevel' => $level,
            'default_duration_sec' => $defaultDuration,
            'extended_duration_sec' => $extendedDuration,
            'theme' => theme_or_default($row['theme'] ?? null),
        ];
    }

    $pdo = db();
    $existingIps = $pdo->query('SELECT user_ip FROM users')->fetchAll(PDO::FETCH_COLUMN) ?: [];
    $existingMap = array_fill_keys($existingIps, true);
    $seenPayload = [];
    $imported = 0;
    $skippedExisting = 0;
    $skippedDuplicate = 0;

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('INSERT INTO users (username, user_ip, otp_secret, role, accesslevel, default_duration_sec, extended_duration_sec, theme)
            VALUES (:n, :u, :o, :r, :a, :dd, :ed, :t)');
        foreach ($clean as $row) {
            if (isset($seenPayload[$row['user_ip']])) {
                $skippedDuplicate++;
                continue;
            }
            $seenPayload[$row['user_ip']] = true;
            if (isset($existingMap[$row['user_ip']])) {
                $skippedExisting++;
                continue;
            }
            $stmt->execute([
                ':n' => $row['username'],
                ':u' => $row['user_ip'],
                ':o' => $row['otp_secret'],
                ':r' => $row['role'],
                ':a' => $row['accesslevel'],
                ':dd' => $row['default_duration_sec'],
                ':ed' => $row['extended_duration_sec'],
                ':t' => $row['theme'],
            ]);
            $imported++;
        }
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return [
        'imported' => $imported,
        'skipped_existing' => $skippedExisting,
        'skipped_duplicate' => $skippedDuplicate,
    ];
}

// ---------------------------------------------------------------------------------------------------------------
// Full backup: every table of the database as JSON (users with OTP secrets, networks, default networks, settings,
// audit log, monitoring data, alerts …). Not included: environment variables and the files in DATA_DIR (GeoIP
// databases, generated pseudonym key, automatic SQLite backups).

const FULL_BACKUP_FORMAT = 'panag-full-backup';
const FULL_BACKUP_VERSION = 1;

/** @return list<string> user tables of $pdo (schema $schema), sorted */
function backup_tables(PDO $pdo, string $schema = 'main'): array
{
    $rows = $pdo->query('SELECT name FROM ' . $schema . ".sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN);
    return array_map('strval', $rows ?: []);
}

/** @return list<string> */
function backup_table_columns(PDO $pdo, string $table, string $schema = 'main'): array
{
    $cols = $pdo->query('PRAGMA ' . $schema . '.table_info(' . backup_quote_ident($table) . ')')->fetchAll(PDO::FETCH_ASSOC);
    return array_map(fn($c) => (string)$c['name'], $cols);
}

function backup_quote_ident(string $name): string
{
    return '"' . str_replace('"', '""', $name) . '"';
}

/** @return array<string, mixed> */
function export_full_backup(PDO $pdo, int $now): array
{
    $tables = [];
    foreach (backup_tables($pdo) as $table) {
        $tables[$table] = $pdo->query('SELECT * FROM ' . backup_quote_ident($table))->fetchAll(PDO::FETCH_ASSOC);
    }
    $sequences = [];
    if ((int)$pdo->query("SELECT COUNT(*) FROM sqlite_master WHERE name = 'sqlite_sequence'")->fetchColumn() > 0) {
        foreach ($pdo->query('SELECT name, seq FROM sqlite_sequence')->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $sequences[(string)$row['name']] = (int)$row['seq'];
        }
    }
    return [
        'format' => FULL_BACKUP_FORMAT,
        'version' => FULL_BACKUP_VERSION,
        'app_version' => APP_VERSION,
        'schema_version' => schema_version($pdo),
        'created_at' => date(DATE_ATOM, $now),
        'tables' => $tables,
        'sequences' => $sequences,
    ];
}

function export_full_backup_json(PDO $pdo, int $now): string
{
    return (string)json_encode(export_full_backup($pdo, $now), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
}

/**
 * Validate a full backup and load it into a fresh database file: created at the backup's schema version, filled,
 * then migrated to the current schema. Throws InvalidArgumentException for anything that does not fit.
 * @return array{path: string, schema_from: int, tables: int, rows: int}
 */
function full_backup_stage(string $json, string $dir): array
{
    $data = json_decode($json, true);
    if (!is_array($data) || ($data['format'] ?? null) !== FULL_BACKUP_FORMAT) {
        throw new InvalidArgumentException('This is not a PANAG full backup.');
    }
    if (($data['version'] ?? null) !== FULL_BACKUP_VERSION) {
        throw new InvalidArgumentException('Unsupported backup format version.');
    }
    $schema = $data['schema_version'] ?? null;
    if (!is_int($schema) || $schema < 1 || $schema > latest_schema_version()) {
        throw new InvalidArgumentException('The backup has schema version ' . json_encode($schema) . '; this PANAG supports 1 to ' . latest_schema_version() . '.');
    }
    if (!isset($data['tables']) || !is_array($data['tables'])) {
        throw new InvalidArgumentException('The backup contains no tables.');
    }

    if (!is_dir($dir) && !mkdir($dir, 0770, true) && !is_dir($dir)) {
        throw new RuntimeException('Cannot create directory ' . $dir);
    }
    $path = rtrim($dir, '/') . '/restore-' . bin2hex(random_bytes(6)) . '.sqlite';
    $pdo = db_connect('sqlite:' . $path);
    $rows = 0;
    try {
        $pdo->exec('PRAGMA journal_mode = DELETE');
        migrate($pdo, null, $schema);
        $pdo->exec('PRAGMA foreign_keys = OFF'); // rows arrive table by table; checked as a whole below
        $known = array_flip(backup_tables($pdo));
        $pdo->beginTransaction();
        foreach ($data['tables'] as $table => $tableRows) {
            $table = (string)$table;
            if (!isset($known[$table])) {
                throw new InvalidArgumentException('Unknown table in the backup: ' . $table);
            }
            if (!is_array($tableRows)) {
                throw new InvalidArgumentException('Invalid rows for table ' . $table);
            }
            $columns = array_flip(backup_table_columns($pdo, $table));
            $statements = [];
            foreach ($tableRows as $i => $row) {
                if (!is_array($row) || $row === []) {
                    throw new InvalidArgumentException(sprintf('Invalid row %d in table %s', $i, $table));
                }
                foreach ($row as $col => $value) {
                    if (!isset($columns[$col])) {
                        throw new InvalidArgumentException(sprintf('Unknown column %s.%s', $table, $col));
                    }
                    if (!is_scalar($value) && $value !== null) {
                        throw new InvalidArgumentException(sprintf('Invalid value in %s.%s', $table, $col));
                    }
                }
                $keys = array_keys($row);
                $sig = implode("\0", $keys);
                $statements[$sig] ??= $pdo->prepare('INSERT INTO ' . backup_quote_ident($table) . ' (' . implode(', ', array_map('backup_quote_ident', $keys))
                    . ') VALUES (' . implode(', ', array_fill(0, count($keys), '?')) . ')');
                $statements[$sig]->execute(array_values($row));
                $rows++;
            }
        }
        foreach ((array)($data['sequences'] ?? []) as $table => $seq) {
            if (isset($known[(string)$table]) && is_int($seq)) {
                // sqlite_sequence has no column types: cast, or the counter would be stored as text
                $pdo->prepare('UPDATE sqlite_sequence SET seq = MAX(seq, CAST(:s AS INTEGER)) WHERE name = :t')->execute([':s' => $seq, ':t' => (string)$table]);
                $pdo->prepare('INSERT INTO sqlite_sequence (name, seq) SELECT :t, CAST(:s AS INTEGER) WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = :t2)')
                    ->execute([':t' => (string)$table, ':s' => $seq, ':t2' => (string)$table]);
            }
        }
        $pdo->commit();
        $broken = $pdo->query('PRAGMA foreign_key_check')->fetchAll(PDO::FETCH_ASSOC);
        if ($broken) {
            throw new InvalidArgumentException('The backup is inconsistent: ' . count($broken) . ' row(s) reference missing rows (first: table ' . $broken[0]['table'] . ').');
        }
        $pdo->exec('PRAGMA foreign_keys = ON');
        migrate($pdo);
        if ((int)$pdo->query("SELECT COUNT(*) FROM users WHERE role = 'admin'")->fetchColumn() === 0) {
            throw new InvalidArgumentException('The backup contains no admin – restoring it would lock everybody out.');
        }
        $tables = count($data['tables']);
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $pdo = null;
        full_backup_discard($path);
        throw $e;
    }
    $pdo = null;
    return ['path' => $path, 'schema_from' => $schema, 'tables' => $tables, 'rows' => $rows];
}

function full_backup_discard(string $path): void
{
    foreach ([$path, $path . '-wal', $path . '-shm', $path . '-journal'] as $file) {
        if (is_file($file)) {
            @unlink($file);
        }
    }
}

/**
 * Replace ALL data of $pdo with the backup. A copy of the current database goes to $backupDir first.
 * @return array{safety_copy: string, schema_from: int, tables: int, rows: int}
 */
function restore_full_backup(PDO $pdo, string $json, string $backupDir): array
{
    $stage = full_backup_stage($json, $backupDir . '/tmp');
    try {
        $safety = backup_database($pdo, $backupDir, 'before-restore', 10);
        $pdo->exec('ATTACH DATABASE ' . $pdo->quote($stage['path']) . ' AS restore_src');
        try {
            $pdo->exec('BEGIN IMMEDIATE');
            $pdo->exec('PRAGMA defer_foreign_keys = ON');
            $tables = backup_tables($pdo);
            // Empty everything first: deleting a parent later would cascade into rows already copied.
            foreach ($tables as $table) {
                $pdo->exec('DELETE FROM main.' . backup_quote_ident($table));
            }
            $source = array_flip(backup_tables($pdo, 'restore_src'));
            foreach ($tables as $table) {
                if (!isset($source[$table])) {
                    continue;
                }
                $cols = array_values(array_intersect(backup_table_columns($pdo, $table), backup_table_columns($pdo, $table, 'restore_src')));
                $list = implode(', ', array_map('backup_quote_ident', $cols));
                $pdo->exec('INSERT INTO main.' . backup_quote_ident($table) . ' (' . $list . ') SELECT ' . $list . ' FROM restore_src.' . backup_quote_ident($table));
            }
            $pdo->exec('DELETE FROM main.sqlite_sequence');
            $pdo->exec('INSERT INTO main.sqlite_sequence (name, seq) SELECT name, seq FROM restore_src.sqlite_sequence');
            $pdo->exec('COMMIT');
        } catch (Throwable $e) {
            $pdo->exec('ROLLBACK');
            throw $e;
        } finally {
            $pdo->exec('DETACH DATABASE restore_src');
        }
    } finally {
        full_backup_discard($stage['path']);
    }
    return ['safety_copy' => $safety, 'schema_from' => $stage['schema_from'], 'tables' => $stage['tables'], 'rows' => $stage['rows']];
}
