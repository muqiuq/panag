<?php
// Detection rules (docs/plan-security-monitoring.md, chapter 5). Rules produce *findings*; alerts.php bundles
// them into alerts. Findings carry an admin text, an optional user text and "facts" – the only data that may
// later be sent (pseudonymised) to the AI, see ai.php.

const MONITOR_RULES = [
    'W1' => 'New country for the user',
    'W2' => 'Country outside the allowlist',
    'W3' => 'Rapid change to an unknown country',
    'W4' => 'Hosting or VPN network',
    'W5' => 'Endpoint switching back and forth',
    'W6' => 'Unusual data volume',
    'W7' => 'Active peer without PANAG user',
    'P1' => 'Failed logins',
    'P2' => 'Reused one-time password blocked',
    'P3' => 'Activity at an unusual time',
    'P4' => 'Network never used before',
    'P5' => 'Many single grants in a short time',
    'P6' => 'Sensitive admin action',
    'P7' => 'Login right after a suspicious location change',
    'P8' => 'Setup page attacked',
    'M1' => 'Monitoring cannot read the router',
    'U1' => 'User reports: this was not me',
];

/**
 * Rule reference for the admin UI: when each rule fires, with the current settings filled in (admin/rules.php can
 * change them). Keep in sync with the rule code below.
 * @return array<string, array{name: string, severity: list<string>, when: string, asks_user: bool, enabled: bool, severity_override: ?string}>
 */
function monitor_rule_reference(): array
{
    $p = fn(string $name) => rule_param_display($name, rule_param($name));
    $learning = 'Only after the learning phase (' . $p('learning_days') . ' days and ' . BASELINE_MIN_EVENTS . ' events per user).';
    $countries = $p('allowed_countries') === '' ? 'none' : $p('allowed_countries');
    $asns = $p('hosting_asns') === '' ? '' : ' plus AS ' . $p('hosting_asns');
    $when = [
        'W1' => ['medium', 'A WireGuard connection comes from an allowed country this user has never connected from. ' . $learning . ' Before that, new countries are learned without an alert.'],
        'W2' => ['high', 'A WireGuard connection comes from a country outside the allowed countries (' . $countries . ') that is not a known place of the user.'],
        'W3' => ['high', 'The WireGuard endpoint moves to another country, not known for the user, within ' . $p('travel_window') . ' of the last connection.'],
        'W4' => ['medium', 'A WireGuard connection comes from a data centre or VPN network (built-in list' . $asns . ') the user has not confirmed.'],
        'W5' => ['medium', 'The WireGuard endpoint switches at least ' . $p('switch_count') . ' times between the same two addresses within ' . $p('switch_window') . ' – the key may be in use on two devices.'],
        'W6' => ['medium', 'A user transfers more than ' . $p('volume_factor') . '× their usual daily volume, and at least ' . $p('volume_min_mb') . ' MB, over WireGuard in one day. ' . $learning],
        'W7' => ['info', 'A WireGuard peer had a handshake in the last 10 min but belongs to no PANAG user.'],
        'P1' => [['medium', 'high'], $p('failed_logins') . ' failed PANAG logins from one IP within ' . $p('failed_logins_window') . '. High when the login rate limit blocks the IP.'],
        'P2' => ['high', 'A one-time password is used a second time (the login is blocked). The code may have been phished or observed.'],
        'P3' => ['low', 'A login or grant at an hour (±1 h) at which the user was not active in the last ' . BASELINE_DAYS . ' days. ' . $learning],
        'P4' => ['medium', 'A user grants a network they have not used in the last ' . BASELINE_DAYS . ' days. ' . $learning],
        'P5' => ['medium', 'A user grants ' . $p('burst_count') . ' single networks within ' . $p('burst_window') . '.'],
        'P6' => [['info', 'medium'], 'A sensitive admin action: ' . implode(', ', array_map(fn($s) => preg_match('/^[A-Z][a-z]/', $s) ? lcfirst($s) : $s, SENSITIVE_ACTIONS)) . '. Medium when someone is made admin.'],
        'P7' => ['high', 'A PANAG login up to 15 min after (or 10 min before) a WireGuard connection that triggered W1–W5. Joins the alert of that connection.'],
        'P8' => ['high', 'Someone enters a wrong token on the setup page.'],
        'M1' => ['high', 'The monitor could not read the WireGuard peers from the router for ' . $p('router_down') . '.'],
        'U1' => ['high', 'The user answered "That wasn\'t me" to an alert. Their active access was revoked at once.'],
    ];
    $asksUser = ['W1', 'W2', 'W3', 'W4', 'W5', 'P2', 'P7'];
    $out = [];
    foreach (MONITOR_RULES as $code => $name) {
        [$severity, $text] = $when[$code];
        $out[$code] = [
            'name' => $name,
            'severity' => (array)$severity,
            'when' => $text,
            'asks_user' => in_array($code, $asksUser, true),
            'enabled' => rule_enabled($code),
            'severity_override' => rule_severity($code),
        ];
    }
    return $out;
}

/**
 * @param array<string, mixed> $facts
 * @param list<array{0: string, 1: int}> $refs [['wg'|'audit', id]]
 */
function finding(string $rule, string $severity, ?int $userId, string $text, array $facts = [], array $refs = [], string $keyPart = '', bool $notifyUser = false, ?string $userText = null, ?int $at = null): array
{
    return [
        'rule' => $rule,
        'severity' => $severity,
        'user_id' => $userId,
        'text' => $text,
        'user_text' => $userText,
        'facts' => $facts,
        'refs' => $refs,
        'key' => $rule . '|' . ($userId ?? '-') . '|' . $keyPart,
        'notify_user' => $notifyUser,
        'at' => $at ?? time(),
    ];
}

function user_label(array $user): string
{
    return $user['username'] . ' (' . $user['user_ip'] . ')';
}

// --- WireGuard -------------------------------------------------------------------------------------

/** Seconds since the last handshake: RouterOS sends "1m12s" or plain seconds; null = never. */
function parse_wg_handshake_age($value): ?int
{
    if ($value === null || $value === '') {
        return null;
    }
    $value = trim((string)$value);
    return ctype_digit($value) ? (int)$value : parse_routeros_duration($value);
}

/** Current public endpoint IP of a peer (current-endpoint-address, RouterOS 7), '' if none. */
function wg_peer_endpoint(array $peer): string
{
    $raw = (string)($peer['current-endpoint-address'] ?? $peer['endpoint-address'] ?? '');
    $raw = trim($raw, " []");
    return filter_var($raw, FILTER_VALIDATE_IP) ? $raw : '';
}

/**
 * The PANAG user whose user_ip is a host route of the peer (allowed-address "10.8.0.2/32" or "10.8.0.2").
 * Wider ranges (site-to-site peers) are not attributed to a user.
 */
function wg_peer_user(array $peer, array $users): ?array
{
    $hosts = [];
    foreach (array_filter(array_map('trim', explode(',', (string)($peer['allowed-address'] ?? '')))) as $entry) {
        $hosts[normalize_address($entry)] = true;
    }
    foreach ($users as $user) {
        if (isset($hosts[(string)$user['user_ip']])) {
            return $user;
        }
    }
    return null;
}

/** @return array{ok: bool, error: ?string, findings: list<array>, peers: int} */
function monitor_poll_wireguard(int $now): array
{
    $resp = mikrotik_wireguard_peers();
    if (!$resp['success']) {
        return ['ok' => false, 'error' => (string)($resp['error'] ?? 'API error'), 'findings' => [], 'peers' => 0];
    }
    $users = db()->query('SELECT * FROM users')->fetchAll(PDO::FETCH_ASSOC);
    $findings = [];
    $count = 0;
    $today = date('Y-m-d', $now);
    foreach ($resp['data'] as $peer) {
        $key = (string)($peer['public-key'] ?? '');
        if ($key === '' || ($peer['disabled'] ?? 'false') === 'true') {
            continue;
        }
        $count++;
        $user = wg_peer_user($peer, $users);
        $userId = $user ? (int)$user['id'] : null;
        $endpoint = wg_peer_endpoint($peer);
        $age = parse_wg_handshake_age($peer['last-handshake'] ?? null);
        // Byte counters as float: PHP on arm/v7 is 32-bit and (int) would stop at 2 GiB.
        $rx = (float)($peer['rx'] ?? 0);
        $tx = (float)($peer['tx'] ?? 0);
        $prevStmt = db()->prepare('SELECT * FROM wg_peers WHERE public_key = :k');
        $prevStmt->execute([':k' => $key]);
        $prev = $prevStmt->fetch(PDO::FETCH_ASSOC) ?: null;

        // Traffic per day (counters restart when the interface or router restarts).
        if ($prev) {
            $delta = ($rx >= (float)$prev['rx'] ? $rx - (float)$prev['rx'] : $rx) + ($tx >= (float)$prev['tx'] ? $tx - (float)$prev['tx'] : $tx);
            if ($delta > 0) {
                db()->prepare('INSERT INTO wg_traffic_days (public_key, day, bytes) VALUES (:k, :d, :b)
                    ON CONFLICT(public_key, day) DO UPDATE SET bytes = bytes + excluded.bytes')->execute([':k' => $key, ':d' => $today, ':b' => $delta]);
                if ($user) {
                    $findings = array_merge($findings, wg_volume_findings($user, $key, $today, $now));
                }
            }
        }

        $country = $prev['country'] ?? null;
        $asn = $prev['asn'] ?? null;
        $changedAt = $prev['endpoint_changed_at'] ?? null;
        if ($endpoint !== '' && (!$prev || (string)$prev['endpoint'] !== $endpoint)) {
            $geo = geoip()->lookup($endpoint);
            db()->prepare('INSERT INTO wg_endpoints (public_key, user_id, ip, country, asn, asn_org, first_seen, last_seen) VALUES (:k, :u, :ip, :c, :a, :o, :t, :t)')
                ->execute([':k' => $key, ':u' => $userId, ':ip' => $endpoint, ':c' => $geo['country'] ?? null, ':a' => $geo['asn'] ?? null, ':o' => $geo['asn_org'] ?? null, ':t' => $now]);
            $endpointId = (int)db()->lastInsertId();
            $country = $geo['country'] ?? null;
            $asn = $geo['asn'] ?? null;
            $changedAt = $now;
            if ($user && $geo !== null && $geo['available']) {
                $new = rules_apply(wg_endpoint_findings($user, $key, $geo, $endpointId, $now)); // disabled rules do not count
                if ($new) {
                    db()->prepare('UPDATE wg_endpoints SET suspicious = 1 WHERE id = :id')->execute([':id' => $endpointId]);
                }
                $findings = array_merge($findings, $new);
            }
        } elseif ($endpoint !== '') {
            db()->prepare('UPDATE wg_endpoints SET last_seen = :t WHERE id = (SELECT MAX(id) FROM wg_endpoints WHERE public_key = :k)')->execute([':t' => $now, ':k' => $key]);
        }

        if (!$user && $age !== null && $age < 600) {
            $name = (string)($peer['name'] ?? $peer['comment'] ?? '');
            $findings[] = finding('W7', 'info', null, 'WireGuard peer "' . $name . '" (' . ($peer['allowed-address'] ?? '?') . ') is active but belongs to no PANAG user.', [], [], $key);
        }

        db()->prepare('INSERT INTO wg_peers (public_key, name, user_id, endpoint, country, asn, last_handshake_at, rx, tx, endpoint_changed_at, polled_at)
            VALUES (:k, :n, :u, :e, :c, :a, :h, :rx, :tx, :ch, :t)
            ON CONFLICT(public_key) DO UPDATE SET name = excluded.name, user_id = excluded.user_id, endpoint = excluded.endpoint, country = excluded.country,
              asn = excluded.asn, last_handshake_at = excluded.last_handshake_at, rx = excluded.rx, tx = excluded.tx,
              endpoint_changed_at = excluded.endpoint_changed_at, polled_at = excluded.polled_at')
            ->execute([':k' => $key, ':n' => (string)($peer['name'] ?? ''), ':u' => $userId, ':e' => $endpoint !== '' ? $endpoint : ($prev['endpoint'] ?? null),
                ':c' => $country, ':a' => $asn, ':h' => $age === null ? null : $now - $age, ':rx' => $rx, ':tx' => $tx, ':ch' => $changedAt, ':t' => $now]);
    }
    return ['ok' => true, 'error' => null, 'findings' => $findings, 'peers' => $count];
}

/**
 * Rules W1–W5 for a new endpoint of a user's peer.
 * @param array{country: ?string, asn: ?int, asn_org: ?string} $geo
 */
function wg_endpoint_findings(array $user, string $peerKey, array $geo, int $endpointId, int $now): array
{
    $userId = (int)$user['id'];
    $country = $geo['country'] ?? '??';
    $known = place_is_known($userId, 'country', $country);
    $allowed = in_array($country, array_map('strtoupper', (array)rule_param('allowed_countries')), true);
    $knownCountries = known_countries($userId);
    $mature = baseline_mature(baseline_for($userId), $now);
    $asnType = is_hosting_asn($geo['asn']) ? 'hosting' : 'other';
    $facts = ['country' => $country, 'asn' => $geo['asn'], 'asn_org' => $geo['asn_org'], 'asn_type' => $asnType, 'known_countries' => $knownCountries];
    $where = $country === '??' ? 'an unknown country' : $country;
    $via = $geo['asn'] ? ' via AS' . $geo['asn'] . ($geo['asn_org'] ? ' ' . $geo['asn_org'] : '') : '';
    $refs = [['wg', $endpointId]];
    $findings = [];

    if (!$known) {
        if (!$allowed) {
            $findings[] = finding('W2', 'high', $userId, 'WireGuard connection of ' . user_label($user) . ' from ' . $where . $via . ' – outside the allowed countries.',
                $facts, $refs, $country, true, 'A WireGuard connection with your key came from ' . $where . '.', $now);
        } elseif ($mature && $knownCountries !== []) {
            $findings[] = finding('W1', 'medium', $userId, 'WireGuard connection of ' . user_label($user) . ' from ' . $where . $via . ' – a country new for this user (known: ' . implode(', ', $knownCountries) . ').',
                $facts, $refs, $country, true, 'A WireGuard connection with your key came from ' . $where . ', which is new for you.', $now);
            place_remember($userId, 'country', $country, 'pending', $now);
        } else {
            place_remember($userId, 'country', $country, 'learned', $now); // learning phase or no history: no alert
        }
    } else {
        place_remember($userId, 'country', $country, 'learned', $now); // refreshes last_seen only
    }

    // W3: rapid change to a country the user is not known for.
    $prev = db()->prepare('SELECT country, last_seen FROM wg_endpoints WHERE user_id = :u AND id < :id AND country IS NOT NULL ORDER BY id DESC LIMIT 1');
    $prev->execute([':u' => $userId, ':id' => $endpointId]);
    $before = $prev->fetch(PDO::FETCH_ASSOC);
    if ($before && $before['country'] !== $country && !$known && $now - (int)$before['last_seen'] <= (int)rule_param('travel_window')) {
        $minutes = (int)round(($now - (int)$before['last_seen']) / 60);
        $within = $minutes < 1 ? 'less than a minute' : $minutes . ' min';
        $findings[] = finding('W3', 'high', $userId, 'WireGuard endpoint of ' . user_label($user) . ' changed from ' . $before['country'] . ' to ' . $where . ' within ' . $within . '.',
            $facts + ['from_country' => (string)$before['country'], 'minutes' => $minutes], $refs, $before['country'] . '>' . $country, true,
            'Your WireGuard connection moved from ' . $before['country'] . ' to ' . $where . ' within ' . $within . '.', $now);
    }

    // W4: hosting / VPN networks, unless the user confirmed that network.
    if ($asnType === 'hosting' && !place_is_known($userId, 'asn', (string)$geo['asn'])) {
        $findings[] = finding('W4', 'medium', $userId, 'WireGuard connection of ' . user_label($user) . ' from a hosting/VPN network' . $via . ' (' . $where . ').',
            $facts, $refs, 'AS' . $geo['asn'], true, 'A WireGuard connection with your key came from a data centre or VPN service' . $via . '.', $now);
    }

    // W5: switching back and forth between two endpoints (same key on two devices?).
    $recent = db()->prepare('SELECT ip FROM wg_endpoints WHERE public_key = :k AND first_seen >= :t ORDER BY id');
    $switchWindow = (int)rule_param('switch_window');
    $recent->execute([':k' => $peerKey, ':t' => $now - $switchWindow]);
    $ips = array_map('strval', $recent->fetchAll(PDO::FETCH_COLUMN));
    if (count($ips) - 1 >= (int)rule_param('switch_count') && count(array_unique($ips)) === 2) {
        $findings[] = finding('W5', 'medium', $userId, 'WireGuard endpoint of ' . user_label($user) . ' switched ' . (count($ips) - 1) . ' times between two addresses within ' . format_duration_human($switchWindow) . ' – is the key used on two devices?',
            ['count' => count($ips) - 1, 'window_minutes' => intdiv($switchWindow, 60)], $refs, $peerKey . '|' . intdiv($now, $switchWindow), true,
            'Your WireGuard key seems to be in use on two devices at the same time.', $now);
    }
    return $findings;
}

/** W6: today's volume far above the user's usual daily volume (mature baseline only). */
function wg_volume_findings(array $user, string $peerKey, string $day, int $now): array
{
    $baseline = baseline_for((int)$user['id']);
    if (!baseline_mature($baseline, $now)) {
        return [];
    }
    $stmt = db()->prepare('SELECT bytes, alerted FROM wg_traffic_days WHERE public_key = :k AND day = :d');
    $stmt->execute([':k' => $peerKey, ':d' => $day]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $typical = (float)($baseline['traffic_p90'] ?? 0);
    $threshold = max((int)rule_param('volume_factor') * $typical, (int)rule_param('volume_min_mb') * 1024 * 1024);
    if (!$row || (int)$row['alerted'] === 1 || (float)$row['bytes'] <= $threshold) {
        return [];
    }
    db()->prepare('UPDATE wg_traffic_days SET alerted = 1 WHERE public_key = :k AND day = :d')->execute([':k' => $peerKey, ':d' => $day]);
    $mb = (int)round((float)$row['bytes'] / 1048576);
    return [finding('W6', 'medium', (int)$user['id'], user_label($user) . ' transferred ' . $mb . ' MB over WireGuard today (usually up to ' . (int)round($typical / 1048576) . ' MB).',
        ['megabytes_today' => $mb, 'typical_megabytes' => (int)round($typical / 1048576)], [], $peerKey . '|' . $day, false, null, $now)];
}

// --- PANAG audit log -------------------------------------------------------------------------------

const SENSITIVE_ACTIONS = [
    'otp_revealed' => 'OTP secret revealed',
    'otp_secret_changed' => 'OTP secret replaced',
    'impersonate_start' => 'Impersonation started',
    'user_created' => 'User created',
    'user_deleted' => 'User deleted',
    'user_role_changed' => 'Role changed',
    'network_updated' => 'Network changed',
    'network_deleted' => 'Network deleted',
    'monitor_rules_changed' => 'Detection rules changed',
    'full_backup_restored' => 'Full backup restored',
    'setup_admin_created' => 'Admin created via setup',
    'cli_admin_created' => 'Admin created on the command line',
];

/** Rules P1–P8 for audit log entries added since the last cycle. @return list<array> */
function monitor_audit_findings(int $now): array
{
    $cursor = monitor_state('monitor.audit_cursor');
    if ($cursor === null) {
        // First run: start now, do not alert on history.
        monitor_state_set('monitor.audit_cursor', (int)db()->query('SELECT COALESCE(MAX(id), 0) FROM audit_log')->fetchColumn());
        return [];
    }
    $stmt = db()->prepare('SELECT * FROM audit_log WHERE id > :c ORDER BY id LIMIT 2000');
    $stmt->execute([':c' => (int)$cursor]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if (!$rows) {
        return [];
    }
    $findings = [];
    $users = array_column(db()->query('SELECT * FROM users')->fetchAll(PDO::FETCH_ASSOC), null, 'id');
    foreach ($rows as $row) {
        $findings = array_merge($findings, audit_row_findings($row, $users, $now));
    }
    monitor_state_set('monitor.audit_cursor', (int)end($rows)['id']);
    return $findings;
}

function audit_row_findings(array $row, array $users, int $now): array
{
    $action = (string)$row['action'];
    $at = (int)$row['created_at'];
    $user = $row['user_id'] !== null ? ($users[(int)$row['user_id']] ?? null) : null;
    $refs = [['audit', (int)$row['id']]];
    $findings = [];
    switch ($action) {
        case 'login_failed':
            $target = $user ?? fetch_user_by_user_ip((string)$row['user_ip']);
            $count = db()->prepare("SELECT COUNT(*) FROM audit_log WHERE action = 'login_failed' AND user_ip = :ip AND created_at BETWEEN :from AND :to AND id <= :id");
            $window = (int)rule_param('failed_logins_window');
            $count->execute([':ip' => $row['user_ip'], ':from' => $at - $window, ':to' => $at, ':id' => $row['id']]);
            $n = (int)$count->fetchColumn();
            if ($n === (int)rule_param('failed_logins')) {
                $who = $target ? user_label($target) : 'IP ' . $row['user_ip'];
                $findings[] = finding('P1', 'medium', $target ? (int)$target['id'] : null, $n . ' failed PANAG logins for ' . $who . ' within ' . format_duration_human($window) . '.',
                    ['count' => $n, 'window_minutes' => intdiv($window, 60)], $refs, (string)$row['user_ip'], false, null, $at);
            }
            break;
        case 'login_rate_limited':
            $target = $user ?? fetch_user_by_user_ip((string)$row['user_ip']);
            $findings[] = finding('P1', 'high', $target ? (int)$target['id'] : null, 'PANAG login blocked after too many failed attempts for ' . ($target ? user_label($target) : 'IP ' . $row['user_ip']) . '.',
                ['count' => (int)MAX_LOGIN_ATTEMPTS_PER_HOUR], $refs, 'rate|' . $row['user_ip'], false, null, $at);
            break;
        case 'otp_reuse_blocked':
            if ($user) {
                $findings[] = finding('P2', 'high', (int)$user['id'], 'A one-time password of ' . user_label($user) . ' was used twice – the code may have been phished or observed.',
                    [], $refs, (string)$row['id'], true, 'Someone tried to log in with a one-time password of yours that had already been used.', $at);
            }
            break;
        case 'setup_token_invalid':
            $findings[] = finding('P8', 'high', null, 'Invalid setup token from ' . ($row['user_ip'] ?: $row['ip']) . ' – someone is trying the setup page.', [], $refs, (string)$row['ip'], false, null, $at);
            break;
        case 'login_success':
        case 'default_access_granted':
        case 'extended_access_granted':
            if ($user) {
                $findings = array_merge($findings, activity_findings($row, $user, $refs, $now));
            }
            break;
        default:
            if (isset(SENSITIVE_ACTIONS[$action])) {
                $meta = $row['meta'] ? json_decode((string)$row['meta'], true) : null;
                $toAdmin = $action === 'user_role_changed' && (($meta['to'] ?? null) === 'admin' || preg_match('/-> admin$/', (string)$row['details']));
                $findings[] = finding('P6', $toAdmin ? 'medium' : 'info', $user ? (int)$user['id'] : null,
                    SENSITIVE_ACTIONS[$action] . ': ' . ($row['details'] ?: $action) . ($row['username'] ? ' (' . $row['username'] . ')' : '') . '.',
                    ['action' => $action] + ($toAdmin ? ['role_to' => 'admin'] : []), $refs, (string)$row['id'], false, null, $at);
            }
    }
    return $findings;
}

/** P3, P4, P5, P7 for logins and grants. */
function activity_findings(array $row, array $user, array $refs, int $now): array
{
    $userId = (int)$user['id'];
    $at = (int)$row['created_at'];
    $baseline = baseline_for($userId);
    $mature = baseline_mature($baseline, $now);
    $findings = [];
    $hour = (int)date('G', $at);

    if ($mature) {
        $hours = $baseline['hours'];
        if (($hours[$hour] + $hours[($hour + 23) % 24] + $hours[($hour + 1) % 24]) === 0) {
            $findings[] = finding('P3', 'low', $userId, user_label($user) . ' is active at ' . sprintf('%02d:00', $hour) . ' – never active around this time in the last ' . BASELINE_DAYS . ' days (' . str_replace('_', ' ', (string)$row['action']) . ').',
                ['local_hour' => $hour, 'usual_hours' => baseline_usual_hours($baseline)], $refs, date('Y-m-d', $at), false, null, $at);
        }
    }

    if ($row['action'] === 'extended_access_granted') {
        $byName = array_column(get_all_networks(), null, 'name');
        $byId = array_column(get_all_networks(), null, 'id');
        if ($mature) {
            foreach (audit_row_network_ids($row, array_map(fn($n) => (int)$n['id'], $byName)) as $id) {
                if (!isset($baseline['networks'][$id]) && !isset($baseline['networks'][(string)$id]) && isset($byId[$id])) {
                    $level = (int)$byId[$id]['accesslevel'];
                    $findings[] = finding('P4', 'medium', $userId, user_label($user) . ' granted "' . $byId[$id]['name'] . '" (L' . $level . ') – not used by this user in the last ' . BASELINE_DAYS . ' days.',
                        ['network_level' => $level, 'user_level' => (int)$user['accesslevel'], 'network_known' => false], $refs, (string)$id, false, null, $at);
                }
            }
        }
        $burst = db()->prepare("SELECT COUNT(*) FROM audit_log WHERE user_id = :u AND action = 'extended_access_granted' AND created_at BETWEEN :f AND :t AND id <= :id");
        $burstWindow = (int)rule_param('burst_window');
        $burst->execute([':u' => $userId, ':f' => $at - $burstWindow, ':t' => $at, ':id' => $row['id']]);
        $n = (int)$burst->fetchColumn();
        if ($n === (int)rule_param('burst_count')) {
            $findings[] = finding('P5', 'medium', $userId, user_label($user) . ' granted ' . $n . ' single networks within ' . format_duration_human($burstWindow) . '.', ['count' => $n, 'window_minutes' => intdiv($burstWindow, 60)], $refs, (string)intdiv($at, $burstWindow), false, null, $at);
        }
    }

    if ($row['action'] === 'login_success') {
        // The endpoint is only seen at the next poll (every 5 min) – so it may be recorded after the login.
        $ep = db()->prepare('SELECT id, country, first_seen FROM wg_endpoints WHERE user_id = :u AND suspicious = 1 AND first_seen BETWEEN :f AND :t ORDER BY id DESC LIMIT 1');
        $ep->execute([':u' => $userId, ':f' => $at - 900, ':t' => $at + 600]);
        if ($hit = $ep->fetch(PDO::FETCH_ASSOC)) {
            // The login may be the user answering the location alert – so P7 joins that alert instead of asking
            // again, and is dropped once the user confirmed the place ("That was me").
            $rel = db()->prepare("SELECT a.id, a.user_response, a.status FROM alert_events e JOIN alerts a ON a.id = e.alert_id WHERE e.ref_type = 'wg' AND e.ref_id = :id ORDER BY a.id DESC LIMIT 1");
            $rel->execute([':id' => $hit['id']]);
            $related = $rel->fetch(PDO::FETCH_ASSOC) ?: null;
            // Dropped when the user confirmed the place or an admin judged the location alert harmless.
            if (($related['user_response'] ?? null) !== 'me' && !in_array($related['status'] ?? null, ['false_positive', 'resolved'], true)) {
                $minutes = max(0, (int)round(($at - (int)$hit['first_seen']) / 60));
                $p7 = finding('P7', 'high', $userId, user_label($user) . ' logged in to PANAG ' . $minutes . ' min after a suspicious WireGuard location (' . ($hit['country'] ?? '??') . ').',
                    ['minutes_since_change' => $minutes, 'country' => (string)($hit['country'] ?? '??')], array_merge($refs, [['wg', (int)$hit['id']]]), (string)$hit['id'], $related === null,
                    'Someone logged in to PANAG with your account right after the unusual connection.', $at);
                if ($related !== null) {
                    $p7['attach_to'] = (int)$related['id'];
                }
                $findings[] = $p7;
            }
        }
    }
    return $findings;
}

/** M1: the router could not be read for 30 min. */
function monitor_health_findings(int $now): array
{
    $ok = (int)monitor_state('monitor.last_poll_ok_at', 0);
    $first = (int)monitor_state('monitor.first_run_at', $now);
    $since = $ok > 0 ? $ok : $first;
    if ($now - $since < (int)rule_param('router_down')) {
        return [];
    }
    $error = (string)monitor_state('monitor.last_poll_error', 'unknown error');
    return [finding('M1', 'high', null, 'The monitor could not read the WireGuard peers from the router for ' . (int)round(($now - $since) / 60) . ' min: ' . $error, [], [], 'router', false, null, $now)];
}
