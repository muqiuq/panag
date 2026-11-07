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
        $clean[] = ['name' => $name, 'address' => $address, 'accesslevel' => $level];
    }

    $pdo = db();
    $pdo->beginTransaction();
    try {
        if ($replace) {
            $pdo->exec('DELETE FROM networks');
        }
        $stmt = $pdo->prepare('INSERT INTO networks (name, accesslevel, address) VALUES (:n, :a, :addr)');
        foreach ($clean as $row) {
            $stmt->execute([
                ':n' => $row['name'],
                ':a' => $row['accesslevel'],
                ':addr' => $row['address'],
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
            'theme' => preg_match('/^[a-z0-9-]{1,32}$/', (string)($row['theme'] ?? '')) ? (string)$row['theme'] : 'default',
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
