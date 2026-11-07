<?php
// Alerts: findings are de-duplicated (MONITOR_COOLDOWN), bundled per user (MONITOR_BUNDLE_WINDOW) and stored.
// Status workflow for admins, "That was me" / "That wasn't me" for the affected user.

const ALERT_STATUSES = [
    'open' => 'Open',
    'acknowledged' => 'Acknowledged',
    'false_positive' => 'False positive',
    'confirmed' => 'Confirmed incident',
    'resolved' => 'Resolved',
];

function alert_key_recent(string $key, int $since): bool
{
    $stmt = db()->prepare('SELECT 1 FROM alert_keys WHERE dedupe_key = :k AND created_at >= :t LIMIT 1');
    $stmt->execute([':k' => $key, ':t' => $since]);
    return (bool)$stmt->fetchColumn();
}

/** Stored finding (no refs/key – they live in alert_events / alert_keys). */
function finding_for_storage(array $f): array
{
    return ['rule' => $f['rule'], 'severity' => $f['severity'], 'at' => $f['at'], 'text' => $f['text'], 'user_text' => $f['user_text'], 'facts' => $f['facts']];
}

function alert_summary(array $findings): string
{
    usort($findings, fn($a, $b) => severity_rank($b['severity']) <=> severity_rank($a['severity']));
    $more = count($findings) - 1;
    return $findings[0]['text'] . ($more > 0 ? ' (+' . $more . ' more)' : '');
}

/**
 * Turn findings into alerts. @return list<int> ids of new or changed alerts (to triage and notify)
 */
function monitor_create_alerts(array $findings, int $now): array
{
    $groups = [];
    $seen = [];
    foreach ($findings as $f) {
        if (isset($seen[$f['key']]) || alert_key_recent($f['key'], $now - MONITOR_COOLDOWN)) {
            continue;
        }
        $seen[$f['key']] = true;
        // attach_to: the finding belongs to a known alert (e.g. P7 to the alert of its location change)
        $group = isset($f['attach_to']) ? 'a' . $f['attach_to'] : ($f['user_id'] !== null ? 'u' . $f['user_id'] : 'sys|' . $f['rule'] . '|' . $f['key']);
        $groups[$group][] = $f;
    }

    $changed = [];
    foreach ($groups as $items) {
        $userId = $items[0]['user_id'];
        $user = $userId !== null ? fetch_user_by_id((int)$userId) : null;
        $severity = array_reduce($items, fn($carry, $f) => severity_max($carry, $f['severity']), 'info');
        $notifyUser = MONITOR_NOTIFY_USERS && array_reduce($items, fn($carry, $f) => $carry || $f['notify_user'], false);
        $stored = array_map('finding_for_storage', $items);

        $existing = isset($items[0]['attach_to']) ? fetch_alert((int)$items[0]['attach_to']) : null;
        if ($existing === null && $userId !== null) {
            $stmt = db()->prepare("SELECT * FROM alerts WHERE user_id = :u AND status = 'open' AND user_response IS NULL AND updated_at >= :t ORDER BY id DESC LIMIT 1");
            $stmt->execute([':u' => $userId, ':t' => $now - MONITOR_BUNDLE_WINDOW]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
        }

        if ($existing) {
            $all = array_merge(json_decode((string)$existing['findings'], true) ?: [], $stored);
            $newSeverity = severity_max((string)$existing['severity'], $severity);
            $oldRules = explode(',', (string)$existing['rules']);
            $rules = array_values(array_unique(array_merge($oldRules, array_column($items, 'rule'))));
            $askUser = !(int)$existing['notify_user'] && $notifyUser && $existing['user_response'] === null;
            db()->prepare('UPDATE alerts SET updated_at = :t, rules = :r, severity = :s, notify_user = :n, summary = :sum, findings = :f WHERE id = :id')
                ->execute([':t' => $now, ':r' => implode(',', $rules), ':s' => $newSeverity, ':n' => ((int)$existing['notify_user'] || $askUser) ? 1 : 0,
                    ':sum' => alert_summary($all), ':f' => json_encode($all, JSON_INVALID_UTF8_SUBSTITUTE), ':id' => $existing['id']]);
            // New kinds of findings, more serious, or the user is to be asked now: mail again with the new findings.
            if (array_diff($rules, $oldRules) || severity_rank($newSeverity) > severity_rank((string)$existing['severity']) || $askUser) {
                alert_reset_delivery((int)$existing['id']);
            }
            $alertId = (int)$existing['id'];
        } else {
            db()->prepare('INSERT INTO alerts (created_at, updated_at, user_id, user_label, rules, severity, notify_user, summary, findings)
                VALUES (:t, :t, :u, :l, :r, :s, :n, :sum, :f)')
                ->execute([':t' => $now, ':u' => $userId, ':l' => $user ? user_label($user) : null, ':r' => implode(',', array_values(array_unique(array_column($items, 'rule')))),
                    ':s' => $severity, ':n' => $notifyUser ? 1 : 0, ':sum' => alert_summary($stored), ':f' => json_encode($stored, JSON_INVALID_UTF8_SUBSTITUTE)]);
            $alertId = (int)db()->lastInsertId();
        }

        $keyStmt = db()->prepare('INSERT INTO alert_keys (dedupe_key, alert_id, created_at) VALUES (:k, :a, :t)');
        $refStmt = db()->prepare('INSERT OR IGNORE INTO alert_events (alert_id, ref_type, ref_id) VALUES (:a, :type, :id)');
        foreach ($items as $f) {
            $keyStmt->execute([':k' => $f['key'], ':a' => $alertId, ':t' => $now]);
            foreach ($f['refs'] as [$type, $id]) {
                $refStmt->execute([':a' => $alertId, ':type' => $type, ':id' => $id]);
            }
        }
        $changed[] = $alertId;
    }
    return array_values(array_unique($changed));
}

function alert_reset_delivery(int $alertId): void
{
    db()->prepare('DELETE FROM alert_deliveries WHERE alert_id = :a')->execute([':a' => $alertId]);
    db()->prepare('UPDATE alerts SET notified_at = NULL, notify_attempts = 0, notify_error = NULL WHERE id = :a')->execute([':a' => $alertId]);
}

function fetch_alert(int $id): ?array
{
    $stmt = db()->prepare('SELECT * FROM alerts WHERE id = :id');
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

/** @return list<array> */
function alert_findings(array $alert): array
{
    $findings = json_decode((string)$alert['findings'], true);
    return is_array($findings) ? $findings : [];
}

function alert_ai(array $alert): ?array
{
    $ai = $alert['ai'] ? json_decode((string)$alert['ai'], true) : null;
    return is_array($ai) ? $ai : null;
}

function open_alert_count(): int
{
    return (int)db()->query("SELECT COUNT(*) FROM alerts WHERE status = 'open'")->fetchColumn();
}

/** Can the user still answer "Was this you?" (asked, open, not answered yet)? */
function alert_answerable(array $alert, array $user): bool
{
    return (int)$alert['user_id'] === (int)$user['id'] && (int)$alert['notify_user'] === 1 && $alert['status'] === 'open' && $alert['user_response'] === null;
}

/** Alerts that ask this user "Was this you?". */
function alerts_awaiting_user(int $userId): array
{
    $stmt = db()->prepare("SELECT * FROM alerts WHERE user_id = :u AND notify_user = 1 AND user_response IS NULL AND status = 'open' ORDER BY id DESC LIMIT 5");
    $stmt->execute([':u' => $userId]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/** Countries and networks named in the location findings of an alert. @return list<array{0: string, 1: string}> [kind, value] */
function alert_places(array $alert): array
{
    $places = [];
    foreach (alert_findings($alert) as $f) {
        $facts = $f['facts'] ?? [];
        if (in_array($f['rule'], ['W1', 'W2', 'W3'], true) && !empty($facts['country']) && $facts['country'] !== '??') {
            $places['country|' . $facts['country']] = ['country', (string)$facts['country']];
        }
        if ($f['rule'] === 'W4' && !empty($facts['asn'])) {
            $places['asn|' . $facts['asn']] = ['asn', (string)$facts['asn']];
        }
    }
    return array_values($places);
}

function alert_set_status(array $alert, string $status, array $admin, string $comment): void
{
    if (!isset(ALERT_STATUSES[$status])) {
        throw new InvalidArgumentException('Unknown status ' . $status);
    }
    db()->prepare('UPDATE alerts SET status = :s, status_by = :b, status_at = :t, status_comment = :c WHERE id = :id')
        ->execute([':s' => $status, ':b' => $admin['username'], ':t' => time(), ':c' => $comment !== '' ? $comment : null, ':id' => $alert['id']]);
    if ($status === 'confirmed' && $alert['user_id'] !== null) {
        // A confirmed incident: places seen during it must not be learned later.
        db()->prepare("DELETE FROM user_locations WHERE user_id = :u AND source = 'pending'")->execute([':u' => $alert['user_id']]);
    }
    log_event('alert_status_changed', 'Alert #' . $alert['id'] . ' -> ' . $status . ($comment !== '' ? ' (' . $comment . ')' : ''), (int)$admin['id'], $admin['username'], $admin['user_ip']);
}

/**
 * The affected user answers. "me": named countries/networks become known places. "not_me": all access of
 * the user is revoked, pending places are dropped and the admins get the alert again as high.
 * @return string message for the user
 */
function alert_user_respond(array $alert, array $user, string $response): string
{
    if (!alert_answerable($alert, $user)) {
        throw new RuntimeException('Not allowed');
    }
    $now = time();
    db()->prepare('UPDATE alerts SET user_response = :r, user_response_at = :t, updated_at = :t WHERE id = :id')
        ->execute([':r' => $response, ':t' => $now, ':id' => $alert['id']]);
    if ($response === 'me') {
        foreach (alert_places($alert) as [$kind, $value]) {
            place_remember((int)$user['id'], $kind, $value, 'confirmed', $now);
        }
        db()->prepare("UPDATE alerts SET status = 'acknowledged', status_by = :b, status_at = :t, status_comment = 'Confirmed by the user' WHERE id = :id")
            ->execute([':b' => $user['username'], ':t' => $now, ':id' => $alert['id']]);
        log_event('alert_user_response', 'Alert #' . $alert['id'] . ': that was me', (int)$user['id'], $user['username'], $user['user_ip']);
        return 'Thank you. The location is now known for your account.';
    }

    $revoke = remove_address_list_entries((string)$user['user_ip']);
    db()->prepare("DELETE FROM user_locations WHERE user_id = :u AND source = 'pending'")->execute([':u' => $user['id']]);
    $findings = alert_findings($alert);
    $findings[] = finding_for_storage(finding('U1', 'high', (int)$user['id'], user_label($user) . ' reports that this activity was NOT them. ' . ($revoke['success'] ? 'All ' . $revoke['deleted'] . ' active entries were revoked.' : 'Revoking the access failed: ' . $revoke['message']), [], [], '', false, null, $now));
    db()->prepare('UPDATE alerts SET severity = :s, rules = :r, findings = :f, summary = :sum, notify_user = 0 WHERE id = :id')
        ->execute([':s' => severity_max((string)$alert['severity'], 'high'), ':r' => $alert['rules'] . ',U1', ':f' => json_encode($findings, JSON_INVALID_UTF8_SUBSTITUTE), ':sum' => alert_summary($findings), ':id' => $alert['id']]);
    alert_reset_delivery((int)$alert['id']);
    log_event('alert_user_response', 'Alert #' . $alert['id'] . ': that was NOT me – removed ' . $revoke['deleted'] . ' entries', (int)$user['id'], $user['username'], $user['user_ip']);
    return $revoke['success']
        ? 'Your access was revoked and the admins were informed. Please contact them and grant access again only once the cause is clear.'
        : 'The admins were informed. Revoking your access failed – please contact an admin right away.';
}
