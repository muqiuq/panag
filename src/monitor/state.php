<?php
// Runtime state of the monitor (cursor, last run, GeoIP update, AI usage) in the `settings` table.
// Configuration never goes here – it comes from environment variables (src/config.php).

/** @param mixed $default @return mixed */
function monitor_state(string $key, $default = null)
{
    $stmt = db()->prepare('SELECT value FROM settings WHERE key = :k');
    $stmt->execute([':k' => $key]);
    $raw = $stmt->fetchColumn();
    if ($raw === false || $raw === null) {
        return $default;
    }
    $value = json_decode((string)$raw, true);
    return $value ?? $default;
}

/** @param mixed $value */
function monitor_state_set(string $key, $value): void
{
    db()->prepare('INSERT INTO settings (key, value) VALUES (:k, :v) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
        ->execute([':k' => $key, ':v' => json_encode($value)]);
}

const SEVERITIES = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];

function severity_rank(string $severity): int
{
    return SEVERITIES[$severity] ?? 0;
}

function severity_max(string $a, string $b): string
{
    return severity_rank($a) >= severity_rank($b) ? $a : $b;
}

function severity_raise(string $severity, int $steps = 1): string
{
    $names = array_keys(SEVERITIES);
    return $names[min(count($names) - 1, severity_rank($severity) + $steps)];
}

function severity_badge_class(string $severity): string
{
    return ['critical' => 'text-bg-dark', 'high' => 'text-bg-danger', 'medium' => 'text-bg-warning', 'low' => 'text-bg-info'][$severity] ?? 'text-bg-secondary';
}
