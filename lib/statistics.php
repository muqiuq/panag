<?php
require_once __DIR__ . '/functions.php';

function statistics_overview(?array $wireguardPeersRes = null): array
{
    $now = time();
    $midnight = strtotime('today', $now);

    $totalUsers = (int)db()->query('SELECT COUNT(*) FROM users')->fetchColumn();
    // Count unique users (by id/username/ip) who logged in successfully today.
    $stmt = db()->prepare('SELECT COUNT(DISTINCT COALESCE(CAST(user_id AS TEXT), username, user_ip)) FROM audit_log WHERE action = :a AND created_at >= :ts');
    $stmt->execute([':a' => 'login_success', ':ts' => $midnight]);
    $loginsToday = (int)$stmt->fetchColumn();

    $stmtFail = db()->prepare('SELECT COUNT(*) FROM audit_log WHERE action = :a AND created_at >= :ts');
    $stmtFail->execute([':a' => 'login_failed', ':ts' => $midnight]);
    $loginFailsToday = (int)$stmtFail->fetchColumn();

    $stmtAudit = db()->prepare('SELECT COUNT(*) FROM audit_log WHERE created_at >= :ts');
    $stmtAudit->execute([':ts' => $midnight]);
    $auditEventsToday = (int)$stmtAudit->fetchColumn();

    $stmtNet = db()->query('SELECT COUNT(*) FROM networks');
    $totalNetworks = (int)$stmtNet->fetchColumn();

    $accessReport = get_all_address_list_entries();
    $accessCount = $accessReport['success'] && isset($accessReport['data']) && is_array($accessReport['data'])
        ? count($accessReport['data'])
        : null;
    $accessError = $accessReport['success'] ? null : ($accessReport['error'] ?? 'API error');

    $wireguardPeersCount = null;
    if ($wireguardPeersRes !== null) {
        if ($wireguardPeersRes['success'] ?? false) {
            $wireguardPeersCount = is_array($wireguardPeersRes['data']) ? count($wireguardPeersRes['data']) : 0;
        }
    } elseif (function_exists('mikrotik_wireguard_peers')) {
        $wg = mikrotik_wireguard_peers();
        if ($wg['success'] ?? false) {
            $wireguardPeersCount = is_array($wg['data']) ? count($wg['data']) : 0;
        }
    }

    $loginCoverage = $totalUsers > 0 ? round(($loginsToday / $totalUsers) * 100, 1) : null;

    return [
        'total_users' => $totalUsers,
        'logins_today' => $loginsToday,
        'login_fails_today' => $loginFailsToday,
        'audit_events_today' => $auditEventsToday,
        'total_networks' => $totalNetworks,
        'accesses_granted' => $accessCount,
        'access_error' => $accessError,
        'wireguard_peers' => $wireguardPeersCount,
        'login_coverage_pct' => $loginCoverage,
    ];
}
