<?php
// One monitor cycle (triggered every 5 min by the RouterOS scheduler via public/monitor.php, or by
// bin/monitor.php). Each step is isolated: a failing step is reported, the others still run.

/** @return array<string, mixed> statistics of the run */
function run_monitor_cycle(?int $now = null): array
{
    rule_settings_reload(); // bin/monitor.php --loop runs for days – pick up changes from admin/rules.php
    if (!MONITOR_ENABLED) {
        return ['status' => 'disabled'];
    }
    $lock = fopen(rtrim(DATA_DIR, '/') . '/monitor.lock', 'c');
    if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
        return ['status' => 'busy'];
    }
    $started = microtime(true);
    $now = $now ?? time();
    if (monitor_state('monitor.first_run_at') === null) {
        monitor_state_set('monitor.first_run_at', $now);
    }
    $stats = ['status' => 'ok', 'at' => $now, 'peers' => 0, 'findings' => 0, 'alerts' => 0, 'errors' => []];
    $step = function (string $name, callable $fn) use (&$stats) {
        try {
            return $fn();
        } catch (Throwable $e) {
            $stats['errors'][] = $name . ': ' . $e->getMessage();
            error_log('PANAG monitor step ' . $name . ' failed: ' . $e->getMessage());
            return null;
        }
    };

    $stats['geoip'] = $step('geoip', fn() => geoip_maybe_update($now)) ?: [];
    $step('baselines', fn() => monitor_update_baselines($now));

    $findings = [];
    $poll = $step('wireguard', fn() => monitor_poll_wireguard($now));
    if (is_array($poll)) {
        $stats['peers'] = $poll['peers'];
        if ($poll['ok']) {
            monitor_state_set('monitor.last_poll_ok_at', $now);
            $findings = $poll['findings'];
        } else {
            monitor_state_set('monitor.last_poll_error', $poll['error']);
            $stats['errors'][] = 'wireguard: ' . $poll['error'];
        }
    }
    $findings = array_merge($findings, $step('audit', fn() => monitor_audit_findings($now)) ?? []);
    $findings = array_merge($findings, $step('health', fn() => monitor_health_findings($now)) ?? []);
    $findings = rules_apply($findings); // switched-off rules, severity overrides (admin/rules.php)
    $stats['findings'] = count($findings);

    $alertIds = $step('alerts', fn() => monitor_create_alerts($findings, $now)) ?? [];
    $stats['alerts'] = count($alertIds);
    $stats['ai'] = $step('ai', fn() => monitor_ai_triage($alertIds, $now));
    $stats['mail'] = $step('notify', fn() => monitor_notify($now));
    $step('learning', fn() => places_learn_pending($now));
    $step('retention', fn() => monitor_retention($now));

    $stats['duration_ms'] = (int)round((microtime(true) - $started) * 1000);
    if ($stats['errors']) {
        $stats['status'] = 'partial';
    }
    monitor_state_set('monitor.last_run', $stats);
    flock($lock, LOCK_UN);
    fclose($lock);
    return $stats;
}

/**
 * Token for monitor.php: MONITOR_TOKEN, otherwise generated in DATA_DIR/monitor.token. The RouterOS scheduler
 * reads that file through the data mount, so nobody has to copy the token.
 */
function monitor_token(): string
{
    return (string)MONITOR_TOKEN !== '' ? (string)MONITOR_TOKEN : data_dir_secret('monitor.token');
}

/** monitor.php: only from MONITOR_ALLOWED_SOURCES (TCP source, never X-Forwarded-For) and with the monitor token. */
function monitor_request_allowed(string $source, string $token): bool
{
    $expected = monitor_token();
    return $expected !== '' && ip_in_any_cidr($source, MONITOR_ALLOWED_SOURCES) && hash_equals($expected, $token);
}

/** Remove old data (docs/plan-security-monitoring.md, chapter 9). */
function monitor_retention(int $now): void
{
    $ipCutoff = $now - MONITOR_IP_RETENTION_DAYS * 86400;
    db()->prepare('UPDATE wg_endpoints SET ip = NULL WHERE ip IS NOT NULL AND last_seen < :t')->execute([':t' => $ipCutoff]);
    // Peers removed from the router, and endpoints unchanged for longer than the retention (re-read at the next poll).
    db()->prepare('DELETE FROM wg_peers WHERE polled_at < :t')->execute([':t' => $ipCutoff]);
    db()->prepare('UPDATE wg_peers SET endpoint = NULL WHERE endpoint IS NOT NULL AND endpoint_changed_at < :t')->execute([':t' => $ipCutoff]);
    db()->prepare('DELETE FROM wg_endpoints WHERE last_seen < :t')->execute([':t' => $now - 400 * 86400]);
    db()->prepare('DELETE FROM alerts WHERE created_at < :t')->execute([':t' => $now - MONITOR_ALERT_RETENTION_DAYS * 86400]);
    db()->prepare('DELETE FROM alert_keys WHERE created_at < :t')->execute([':t' => $now - max(2 * MONITOR_COOLDOWN, 7 * 86400)]);
    db()->prepare('DELETE FROM wg_traffic_days WHERE day < :d')->execute([':d' => date('Y-m-d', $now - BASELINE_DAYS * 86400)]);
    db()->prepare('DELETE FROM mail_log WHERE created_at < :t')->execute([':t' => $now - 90 * 86400]);
}

/** Last cycle older than 15 min (scheduler not running?). */
function monitor_is_stale(?int $now = null): bool
{
    $last = monitor_state('monitor.last_run');
    return MONITOR_ENABLED && (!is_array($last) || ($now ?? time()) - (int)($last['at'] ?? 0) > 900);
}
