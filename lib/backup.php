<?php
require_once __DIR__ . '/functions.php';

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
    $rows = db()->query('SELECT username, user_ip, otp_secret, isadmin, accesslevel FROM users ORDER BY user_ip')->fetchAll(PDO::FETCH_ASSOC);
    $payload = array_map(function ($u) {
        return [
            'username' => $u['username'] ?? '',
            'user_ip' => $u['user_ip'] ?? '',
            'otp_secret' => $u['otp_secret'] ?? '',
            'isadmin' => isset($u['isadmin']) ? (int)$u['isadmin'] : 0,
            'accesslevel' => isset($u['accesslevel']) ? (int)$u['accesslevel'] : 0,
        ];
    }, $rows);
    return json_encode($payload, JSON_PRETTY_PRINT);
}

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
        $isadmin = isset($row['isadmin']) ? (int)$row['isadmin'] : 0;
        $level = isset($row['accesslevel']) ? (int)$row['accesslevel'] : 0;
        if ($username === '' || $userIp === '' || $otp === '') {
            throw new InvalidArgumentException('Missing username, user_ip, or otp_secret at index ' . $idx);
        }
        if ($level < 0 || $level > (int)MAX_ACCESS_LEVEL) {
            throw new InvalidArgumentException('Invalid access level at index ' . $idx);
        }
        $clean[] = [
            'username' => $username,
            'user_ip' => $userIp,
            'otp_secret' => $otp,
            'isadmin' => $isadmin ? 1 : 0,
            'accesslevel' => $level,
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
        $stmt = $pdo->prepare('INSERT INTO users (username, user_ip, otp_secret, isadmin, accesslevel) VALUES (:n, :u, :o, :i, :a)');
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
                ':i' => $row['isadmin'],
                ':a' => $row['accesslevel'],
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
