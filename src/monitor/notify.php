<?php
// Alert mails. high/critical: right away. medium: right away, but at most one mail per hour (pending medium
// alerts are combined). low/info: daily digest at MONITOR_DIGEST_TIME (admins only).
// Deliveries are tracked per recipient; failed recipients are retried in the next cycles (max. 5 times).

const NOTIFY_MAX_ATTEMPTS = 5;
const NOTIFY_MEDIUM_INTERVAL = 3600;

/** Admin recipients: admins with an address and notifications on, plus ALERT_ADMIN_EMAILS. @return list<string> */
function admin_alert_recipients(): array
{
    $mails = db()->query("SELECT email FROM users WHERE role = 'admin' AND notify_alerts = 1 AND email IS NOT NULL AND email != ''")->fetchAll(PDO::FETCH_COLUMN);
    $all = array_merge(array_map('strval', $mails), array_map('strval', ALERT_ADMIN_EMAILS));
    $valid = array_filter(array_map(fn($m) => strtolower(trim($m)), $all), fn($m) => filter_var($m, FILTER_VALIDATE_EMAIL) !== false);
    return array_values(array_unique($valid));
}

/** The affected user's address when the user is to be asked "Was this you?". */
function alert_user_recipient(array $alert, array $adminRecipients): ?string
{
    if (!(int)$alert['notify_user'] || $alert['user_id'] === null || !MONITOR_NOTIFY_USERS || $alert['user_response'] !== null) {
        return null; // also not once the user has answered (e.g. via the dashboard banner)
    }
    $user = fetch_user_by_id((int)$alert['user_id']);
    $mail = $user && (int)$user['notify_alerts'] === 1 ? strtolower(trim((string)$user['email'])) : '';
    if ($mail === '' || !filter_var($mail, FILTER_VALIDATE_EMAIL) || in_array($mail, $adminRecipients, true)) {
        return null;
    }
    return $mail;
}

function alert_delivered_to(int $alertId): array
{
    $stmt = db()->prepare('SELECT recipient FROM alert_deliveries WHERE alert_id = :a');
    $stmt->execute([':a' => $alertId]);
    return array_map('strval', $stmt->fetchAll(PDO::FETCH_COLUMN));
}

function app_link(string $path): string
{
    $base = rtrim((string)APP_BASE_URL, '/');
    return $base === '' ? '' : $base . '/' . ltrim($path, '/');
}

function mail_footer(): string
{
    return "\n-- \n" . APP_NAME . ' ' . APP_VERSION . ' security monitoring. ' . GEOIP_ATTRIBUTION . "\n";
}

/** One admin mail listing several alerts. @param list<array> $alerts */
function compose_admin_mail(array $alerts): array
{
    usort($alerts, fn($a, $b) => severity_rank((string)$b['severity']) <=> severity_rank((string)$a['severity']));
    $top = (string)$alerts[0]['severity'];
    $subject = count($alerts) === 1
        ? '[' . APP_NAME . '] ' . strtoupper($top) . ': ' . mb_substr_safe((string)$alerts[0]['summary'], 120)
        : '[' . APP_NAME . '] ' . count($alerts) . ' security alerts (highest: ' . strtoupper($top) . ')';
    $body = APP_NAME . " security alert\n";
    foreach ($alerts as $alert) {
        $body .= "\n" . str_repeat('=', 60) . "\n";
        $body .= strtoupper((string)$alert['severity']) . ' – ' . ($alert['user_label'] ?? 'system') . "\n";
        $body .= 'When:  ' . date('Y-m-d H:i', (int)$alert['created_at']) . ' (' . APP_TIMEZONE . ")\n";
        $body .= "What:\n";
        foreach (alert_findings($alert) as $f) {
            $body .= '  - [' . $f['rule'] . ' ' . (MONITOR_RULES[$f['rule']] ?? '') . '] ' . $f['text'] . "\n";
        }
        $ai = alert_ai($alert);
        if ($ai) {
            $body .= 'AI assessment (' . ($ai['model'] ?? 'AI') . '): ' . ($ai['likely_benign'] ? 'probably harmless' : 'probably NOT harmless')
                . ', confidence ' . $ai['confidence'] . ', suggests: ' . str_replace('_', ' ', (string)$ai['recommended_action']) . "\n  " . $ai['summary_admin'] . "\n";
        }
        if ($alert['user_response'] === 'not_me') {
            $body .= "The user answered: THIS WAS NOT ME.\n";
        }
        $link = app_link('admin/alerts.php?id=' . (int)$alert['id']);
        if ($link !== '') {
            $body .= 'Details: ' . $link . "\n";
        }
    }
    return [$subject, $body . mail_footer()];
}

/** Mail to the affected user: plain language, no internal details. @param list<array> $alerts */
function compose_user_mail(array $user, array $alerts): array
{
    $subject = '[' . APP_NAME . '] Was this you? Unusual activity on your account';
    $body = 'Hello ' . $user['username'] . ",\n\n" . APP_NAME . " noticed activity on your account that looks unusual:\n\n";
    foreach ($alerts as $alert) {
        foreach (alert_findings($alert) as $f) {
            if (!empty($f['user_text'])) {
                $body .= '  - ' . date('Y-m-d H:i', (int)$f['at']) . ': ' . $f['user_text'] . "\n";
            }
        }
        $ai = alert_ai($alert);
        if ($ai && $ai['summary_user'] !== '') {
            $body .= "\n" . $ai['summary_user'] . "\n";
        }
        $link = app_link('alert.php?id=' . (int)$alert['id']);
        $body .= "\nPlease tell us whether this was you" . ($link !== '' ? ' (open in the VPN): ' . $link : ' – open ' . APP_NAME . ' via the VPN.') . "\n";
    }
    $body .= "\nIf it was not you, choose \"That wasn't me\": your access is revoked immediately and the admins are informed.\n";
    return [$subject, $body . mail_footer()];
}

/**
 * Send what is due. @param int|null $now for tests
 * @return array{sent: int, failed: int, deferred: int, digest: int, skipped: ?string}
 */
function monitor_notify(?int $now = null): array
{
    $now = $now ?? time();
    $stats = ['sent' => 0, 'failed' => 0, 'deferred' => 0, 'digest' => 0, 'skipped' => null];
    if (($problem = mail_config_problem()) !== null) {
        $stats['skipped'] = $problem;
        return $stats;
    }
    // updated_at: an old alert that changed (new findings, "That wasn't me") is mailed again
    $pending = db()->prepare("SELECT * FROM alerts WHERE notified_at IS NULL AND notify_error IS NULL AND severity IN ('medium', 'high', 'critical') AND updated_at >= :t ORDER BY id");
    $pending->execute([':t' => $now - 7 * 86400]);
    $alerts = $pending->fetchAll(PDO::FETCH_ASSOC);
    if ($alerts) {
        $urgent = array_filter($alerts, fn($a) => severity_rank((string)$a['severity']) >= severity_rank('high'));
        $lastMedium = (int)db()->query("SELECT COALESCE(MAX(created_at), 0) FROM mail_log WHERE kind = 'alert' AND ok = 1")->fetchColumn();
        if (!$urgent && $now - $lastMedium < NOTIFY_MEDIUM_INTERVAL) {
            $stats['deferred'] = count($alerts);
        } else {
            $result = deliver_alerts($alerts, $now);
            $stats['sent'] += $result['sent'];
            $stats['failed'] += $result['failed'];
        }
    }
    $stats['digest'] = monitor_send_digest($now);
    return $stats;
}

/** @param list<array> $alerts @return array{sent: int, failed: int} */
function deliver_alerts(array $alerts, int $now): array
{
    $admins = admin_alert_recipients();
    $sent = 0;
    $failed = 0;
    $errors = [];
    // admin mails: one per recipient with all alerts not yet delivered to them
    foreach ($admins as $to) {
        $todo = array_values(array_filter($alerts, fn($a) => !in_array($to, alert_delivered_to((int)$a['id']), true)));
        if (!$todo) {
            continue;
        }
        [$subject, $body] = compose_admin_mail($todo);
        $error = send_logged_mail('alert', $to, $subject, $body, (string)$todo[0]['severity'], $now);
        if ($error === null) {
            $sent++;
            foreach ($todo as $a) {
                db()->prepare('INSERT OR IGNORE INTO alert_deliveries (alert_id, recipient, delivered_at) VALUES (:a, :r, :t)')->execute([':a' => $a['id'], ':r' => $to, ':t' => $now]);
            }
        } else {
            $failed++;
            foreach ($todo as $a) {
                $errors[(int)$a['id']] = $error;
            }
        }
    }
    // user mails
    $byUser = [];
    foreach ($alerts as $a) {
        $to = alert_user_recipient($a, $admins);
        if ($to !== null && !in_array($to, alert_delivered_to((int)$a['id']), true)) {
            $byUser[$to][] = $a;
        }
    }
    foreach ($byUser as $to => $userAlerts) {
        $user = fetch_user_by_id((int)$userAlerts[0]['user_id']);
        [$subject, $body] = compose_user_mail($user ?? ['username' => ''], $userAlerts);
        $error = send_logged_mail('user', (string)$to, $subject, $body, (string)$userAlerts[0]['severity'], $now);
        if ($error === null) {
            $sent++;
            foreach ($userAlerts as $a) {
                db()->prepare('INSERT OR IGNORE INTO alert_deliveries (alert_id, recipient, delivered_at) VALUES (:a, :r, :t)')->execute([':a' => $a['id'], ':r' => $to, ':t' => $now]);
            }
        } else {
            $failed++;
            foreach ($userAlerts as $a) {
                $errors[(int)$a['id']] = $error;
            }
        }
    }
    // bookkeeping per alert
    foreach ($alerts as $a) {
        $expected = $admins;
        if (($u = alert_user_recipient($a, $admins)) !== null) {
            $expected[] = $u;
        }
        if (!$expected) {
            db()->prepare('UPDATE alerts SET notify_error = :e WHERE id = :id')->execute([':e' => 'No recipients: no admin has an e-mail address and ALERT_ADMIN_EMAILS is empty.', ':id' => $a['id']]);
            continue;
        }
        $missing = array_diff($expected, alert_delivered_to((int)$a['id']));
        if (!$missing) {
            db()->prepare('UPDATE alerts SET notified_at = :t WHERE id = :id')->execute([':t' => $now, ':id' => $a['id']]);
            continue;
        }
        $attempts = (int)$a['notify_attempts'] + 1;
        db()->prepare('UPDATE alerts SET notify_attempts = :n, notify_error = :e WHERE id = :id')
            ->execute([':n' => $attempts, ':e' => $attempts >= NOTIFY_MAX_ATTEMPTS ? ($errors[(int)$a['id']] ?? 'Delivery failed') : null, ':id' => $a['id']]);
    }
    return ['sent' => $sent, 'failed' => $failed];
}

/** Daily digest of low/info alerts to the admins. @return int mails sent */
function monitor_send_digest(int $now): int
{
    if (!preg_match('/^(\d{2}):(\d{2})$/', (string)MONITOR_DIGEST_TIME, $m)) {
        return 0;
    }
    $today = date('Y-m-d', $now);
    $due = strtotime($today . ' ' . $m[1] . ':' . $m[2] . ':00');
    if ($now < $due || monitor_state('monitor.digest_day') === $today) {
        return 0;
    }
    monitor_state_set('monitor.digest_day', $today);
    $stmt = db()->prepare("SELECT * FROM alerts WHERE notified_at IS NULL AND notify_error IS NULL AND severity IN ('info', 'low') ORDER BY id");
    $stmt->execute();
    $alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if (!$alerts) {
        return 0;
    }
    $admins = admin_alert_recipients();
    $sent = 0;
    $body = APP_NAME . ' daily digest – ' . count($alerts) . " low-priority finding(s)\n\n";
    foreach ($alerts as $a) {
        $body .= '- ' . date('Y-m-d H:i', (int)$a['created_at']) . ' [' . $a['rules'] . '] ' . $a['summary'] . "\n";
    }
    $link = app_link('admin/alerts.php');
    $body .= ($link !== '' ? "\nAll alerts: " . $link . "\n" : '') . mail_footer();
    foreach ($admins as $to) {
        if (send_logged_mail('digest', $to, '[' . APP_NAME . '] Daily digest: ' . count($alerts) . ' finding(s)', $body, 'low', $now) === null) {
            $sent++;
        }
    }
    if ($sent > 0 || !$admins) {
        $ids = array_column($alerts, 'id');
        db()->exec('UPDATE alerts SET notified_at = ' . $now . ($admins ? '' : ", notify_error = 'No recipients'") . ' WHERE id IN (' . implode(',', array_map('intval', $ids)) . ')');
    }
    return $sent;
}

/** Test mail from admin/monitoring.php. @return string|null error */
function send_test_mail(string $to): ?string
{
    return send_logged_mail('test', $to, '[' . APP_NAME . '] Test mail', "This is a test mail from " . APP_NAME . " security monitoring.\nIf you can read this, alert mails will arrive.\n" . mail_footer());
}
