<?php
// Per-user baseline over the last 90 days: when the user is usually active, which networks are used,
// typical data volume. Recomputed once a day. Behaviour rules only alert once the baseline is mature
// (MONITOR_LEARNING_DAYS and at least BASELINE_MIN_EVENTS events).

const BASELINE_DAYS = 90;
const BASELINE_MIN_EVENTS = 20;

/** @return array{events: int, first_seen: ?int, hours: list<int>, networks: array<int, int>, logins_per_week: float, grants_per_day: float, traffic_p90: float, computed_at: int} */
function compute_user_baseline(int $userId, int $now): array
{
    $since = $now - BASELINE_DAYS * 86400;
    $hours = array_fill(0, 24, 0);
    $networks = [];
    $events = 0;
    $logins = 0;
    $grants = 0;
    $byName = array_column(get_all_networks(), 'id', 'name');
    $stmt = db()->prepare("SELECT action, created_at, meta, details FROM audit_log
        WHERE user_id = :u AND created_at >= :s AND action IN ('login_success', 'default_access_granted', 'extended_access_granted')");
    $stmt->execute([':u' => $userId, ':s' => $since]);
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $events++;
        $hours[(int)date('G', (int)$row['created_at'])]++;
        if ($row['action'] === 'login_success') {
            $logins++;
            continue;
        }
        $grants++;
        foreach (audit_row_network_ids($row, $byName) as $id) {
            $networks[$id] = ($networks[$id] ?? 0) + 1;
        }
    }
    $first = db()->prepare('SELECT MIN(t) FROM (SELECT MIN(created_at) AS t FROM audit_log WHERE user_id = :u UNION ALL SELECT MIN(first_seen) FROM wg_endpoints WHERE user_id = :u2)');
    $first->execute([':u' => $userId, ':u2' => $userId]);
    $firstSeen = $first->fetchColumn();
    $firstSeen = $firstSeen === null || $firstSeen === false ? null : (int)$firstSeen;
    $spanDays = max(1.0, ($now - ($firstSeen !== null ? max($firstSeen, $since) : $now)) / 86400);

    $traffic = db()->prepare('SELECT t.day, SUM(t.bytes) FROM wg_traffic_days t JOIN wg_peers p ON p.public_key = t.public_key
        WHERE p.user_id = :u AND t.day >= :d AND t.day < :today GROUP BY t.day');
    $traffic->execute([':u' => $userId, ':d' => date('Y-m-d', $now - 30 * 86400), ':today' => date('Y-m-d', $now)]);
    $volumes = array_map('floatval', $traffic->fetchAll(PDO::FETCH_KEY_PAIR)); // float: 32-bit PHP on arm/v7
    sort($volumes);
    $p90 = $volumes ? $volumes[(int)floor(0.9 * (count($volumes) - 1))] : 0;

    return [
        'events' => $events,
        'first_seen' => $firstSeen,
        'hours' => $hours,
        'networks' => $networks,
        'logins_per_week' => round($logins / $spanDays * 7, 1),
        'grants_per_day' => round($grants / $spanDays, 1),
        'traffic_p90' => $p90,
        'computed_at' => $now,
    ];
}

/** Network ids of a grant event: from meta (since V0.2), else matched by name from the details text. */
function audit_row_network_ids(array $row, array $byName): array
{
    $meta = isset($row['meta']) ? json_decode((string)$row['meta'], true) : null;
    if (is_array($meta) && isset($meta['networks']) && is_array($meta['networks'])) {
        return array_map('intval', $meta['networks']);
    }
    if (preg_match('/^Networks: (.*?)(?: \||$)/', (string)($row['details'] ?? ''), $m)) {
        return array_values(array_filter(array_map(fn($n) => isset($byName[trim($n)]) ? (int)$byName[trim($n)] : null, explode(',', $m[1]))));
    }
    return [];
}

function baseline_for(int $userId): ?array
{
    $stmt = db()->prepare('SELECT data FROM user_baselines WHERE user_id = :u');
    $stmt->execute([':u' => $userId]);
    $raw = $stmt->fetchColumn();
    $data = $raw ? json_decode((string)$raw, true) : null;
    return is_array($data) ? $data : null;
}

function baseline_mature(?array $baseline, int $now): bool
{
    return $baseline !== null
        && $baseline['first_seen'] !== null
        && $now - (int)$baseline['first_seen'] >= MONITOR_LEARNING_DAYS * 86400
        && (int)$baseline['events'] >= BASELINE_MIN_EVENTS;
}

/** Recompute all baselines once per day. @return int users computed */
function monitor_update_baselines(int $now, bool $force = false): int
{
    $today = date('Y-m-d', $now);
    if (!$force && monitor_state('monitor.baselines_day') === $today) {
        return 0;
    }
    $count = 0;
    $stmt = db()->prepare('INSERT INTO user_baselines (user_id, data, computed_at) VALUES (:u, :d, :t)
        ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, computed_at = excluded.computed_at');
    foreach (db()->query('SELECT id FROM users')->fetchAll(PDO::FETCH_COLUMN) as $userId) {
        $stmt->execute([':u' => (int)$userId, ':d' => json_encode(compute_user_baseline((int)$userId, $now)), ':t' => $now]);
        $count++;
    }
    monitor_state_set('monitor.baselines_day', $today);
    return $count;
}

/** "07-19": smallest hour range covering 90 % of the activity (for the AI and the admin view). */
function baseline_usual_hours(array $baseline): string
{
    $hours = $baseline['hours'] ?? [];
    $total = array_sum($hours);
    if ($total === 0) {
        return 'unknown';
    }
    $active = array_keys(array_filter($hours, fn($c) => $c > 0));
    return sprintf('%02d-%02d', min($active), max($active) + 1);
}
