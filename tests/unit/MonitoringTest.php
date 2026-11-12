<?php
use PHPUnit\Framework\TestCase;

/** Security monitoring (docs/plan-security-monitoring.md) with fake router, mailer, GeoIP and AI. */
final class MonitoringTest extends TestCase
{
    private FakeRouterClient $router;
    private FakeMailer $mailer;
    /** @var list<array> request bodies sent to the (fake) AI */
    private array $aiRequests = [];
    /** @var array{status: int, body: ?array, error: ?string}|null next AI answer */
    private ?array $aiAnswer = null;
    private int $now;

    protected function setUp(): void
    {
        $pdo = db();
        foreach (['alert_deliveries', 'alert_events', 'alert_keys', 'alerts', 'mail_log', 'user_baselines', 'user_locations', 'wg_traffic_days', 'wg_endpoints', 'wg_peers',
            'settings', 'user_to_network', 'otp_used', 'networks', 'users', 'audit_log', 'login_attempts'] as $table) {
            $pdo->exec("DELETE FROM {$table}");
        }
        rule_settings_reload(); // settings were emptied above
        $this->router = new FakeRouterClient();
        set_router($this->router);
        $this->mailer = new FakeMailer();
        set_mailer($this->mailer);
        set_geoip(new FakeGeoLookup([
            '198.51.100.0/24' => ['country' => 'CH', 'asn' => 3303, 'asn_org' => 'Swisscom'],
            '192.0.2.0/24' => ['country' => 'DE', 'asn' => 3320, 'asn_org' => 'Deutsche Telekom'],
            '203.0.113.0/24' => ['country' => 'US', 'asn' => 14061, 'asn_org' => 'DigitalOcean, LLC'],
            '198.18.1.0/24' => ['country' => 'US', 'asn' => 7922, 'asn_org' => 'Comcast'],
        ]));
        $this->aiRequests = [];
        $this->aiAnswer = null;
        set_ai_transport(function (array $body): array {
            $this->aiRequests[] = $body;
            return $this->aiAnswer ?? self::aiOk(['severity' => 'high', 'likely_benign' => false]);
        });
        $this->now = strtotime('2026-11-07 10:00:00');
    }

    protected function tearDown(): void
    {
        set_router(null);
        set_mailer(null);
        set_geoip(null);
        set_ai_transport(null);
    }

    private static function aiOk(array $override = [], string $finish = 'stop'): array
    {
        $result = $override + ['severity' => 'medium', 'likely_benign' => false, 'confidence' => 'high', 'signals' => ['new country'],
            'summary_admin' => 'Looks like a stolen key.', 'summary_user' => 'Your VPN was used from abroad.', 'recommended_action' => 'ask_user'];
        return ['status' => 200, 'error' => null, 'body' => ['model' => 'z-ai/glm-5.3', 'provider' => 'TestProvider',
            'choices' => [['finish_reason' => $finish, 'message' => ['content' => json_encode($result)]]], 'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 20]]];
    }

    private function user(string $ip, int $level = 5, string $role = 'user', ?string $email = null): array
    {
        save_user(null, 'User ' . $ip, $ip, 'JBSWY3DPEHPK3PXP', $role, $level);
        $user = fetch_user_by_user_ip($ip);
        if ($email !== null) {
            update_user_contact((int)$user['id'], $email, true);
        }
        return fetch_user_by_user_ip($ip);
    }

    private function peer(string $key, string $allowed, string $endpoint, int $rx = 0): void
    {
        foreach ($this->router->peers as $i => $p) {
            if ($p['public-key'] === $key) {
                $this->router->peers[$i]['current-endpoint-address'] = $endpoint;
                $this->router->peers[$i]['rx'] = (string)$rx;
                return;
            }
        }
        $this->router->peers[] = ['.id' => '*' . (count($this->router->peers) + 1), 'interface' => 'wg0', 'name' => 'Laptop of ' . $allowed, 'public-key' => $key,
            'allowed-address' => $allowed, 'current-endpoint-address' => $endpoint, 'last-handshake' => '5s', 'rx' => (string)$rx, 'tx' => '0', 'disabled' => 'false'];
    }

    /** Synthetic 30-day history so behaviour rules are active (logins 08:00–17:00, network $networkId). */
    private function matureBaseline(array $user, ?int $networkId = null): void
    {
        $stmt = db()->prepare('INSERT INTO audit_log (user_id, username, user_ip, action, details, ip, created_at, meta) VALUES (:u, :n, :ip, :a, :d, :ip, :t, :m)');
        for ($day = 30; $day >= 1; $day--) {
            $t = strtotime(date('Y-m-d', $this->now - $day * 86400) . ' ' . (8 + $day % 9) . ':15:00');
            $stmt->execute([':u' => $user['id'], ':n' => $user['username'], ':ip' => $user['user_ip'], ':a' => 'login_success', ':d' => '', ':t' => $t, ':m' => null]);
            if ($networkId !== null) {
                $stmt->execute([':u' => $user['id'], ':n' => $user['username'], ':ip' => $user['user_ip'], ':a' => 'extended_access_granted', ':d' => 'Networks: x', ':t' => $t + 60, ':m' => json_encode(['networks' => [$networkId]])]);
            }
        }
        place_remember((int)$user['id'], 'country', 'CH', 'learned', $this->now - 30 * 86400);
        monitor_update_baselines($this->now, true);
        $this->assertTrue(baseline_mature(baseline_for((int)$user['id']), $this->now));
    }

    private function alerts(): array
    {
        return db()->query('SELECT * FROM alerts ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
    }

    // --- WireGuard / GeoIP ---------------------------------------------------------------------

    public function testAllowedCountryIsLearnedSilently(): void
    {
        $user = $this->user('10.0.0.2');
        $this->peer('key-a', '10.0.0.2/32', '198.51.100.10');
        $poll = monitor_poll_wireguard($this->now);
        $this->assertTrue($poll['ok']);
        $this->assertSame([], $poll['findings']);
        $this->assertTrue(place_is_known((int)$user['id'], 'country', 'CH'));
        $row = db()->query("SELECT * FROM wg_peers WHERE public_key = 'key-a'")->fetch(PDO::FETCH_ASSOC);
        $this->assertSame((int)$user['id'], (int)$row['user_id']);
        $this->assertSame('CH', $row['country']);
        $this->assertSame($this->now - 5, (int)$row['last_handshake_at']);
    }

    public function testForeignHostingEndpointRaisesHighAlertMailsAdminsAndUser(): void
    {
        $user = $this->user('10.0.0.2', 5, 'user', 'regular@example.test');
        $this->peer('key-a', '10.0.0.2/32', '198.51.100.10');
        $this->assertSame('ok', run_monitor_cycle($this->now)['status']);     // learns CH, starts the audit cursor
        $this->peer('key-a', '10.0.0.2/32', '203.0.113.50');
        $stats = run_monitor_cycle($this->now + 300);

        $this->assertSame('ok', $stats['status'], json_encode($stats));
        $alerts = $this->alerts();
        $this->assertCount(1, $alerts, 'findings of one user are bundled');
        $this->assertSame('high', $alerts[0]['severity']);
        $this->assertEqualsCanonicalizing(['W2', 'W3', 'W4'], explode(',', $alerts[0]['rules']));
        $this->assertSame(1, (int)$alerts[0]['notify_user']);
        $this->assertNotNull(alert_ai($alerts[0]), 'triaged by the AI');
        $this->assertNotNull($alerts[0]['notified_at']);

        $this->assertEqualsCanonicalizing(['security@example.test', 'regular@example.test'], $this->mailer->recipients());
        $admin = $this->mailer->sent[array_search('security@example.test', $this->mailer->recipients(), true)];
        $this->assertStringStartsWith('[PANAG] HIGH:', $admin['subject']);
        $this->assertStringNotContainsString('203.0.113.50', $admin['body'], 'public IPs are not copied into alerts (kept 365 days, IPs only 30)');
        $this->assertStringContainsString('US via AS14061 DigitalOcean', $admin['body']);
        $this->assertStringContainsString('https://panag.example.test/admin/alerts.php?id=' . $alerts[0]['id'], $admin['body']);
        $this->assertStringContainsString('AI assessment', $admin['body']);
        $userMail = $this->mailer->sent[array_search('regular@example.test', $this->mailer->recipients(), true)];
        $this->assertStringContainsString('Was this you?', $userMail['subject']);
        $this->assertStringContainsString('https://panag.example.test/alert.php?id=' . $alerts[0]['id'], $userMail['body']);
        $this->assertStringNotContainsString('admin/alerts.php', $userMail['body'], 'no admin links for the user');
        $this->assertStringNotContainsString('203.0.113.50', $userMail['body']);

        run_monitor_cycle($this->now + 600);
        $this->assertCount(2, $this->mailer->sent, 'nothing is sent twice');
        $this->assertTrue((bool)db()->query('SELECT suspicious FROM wg_endpoints ORDER BY id DESC LIMIT 1')->fetchColumn());
    }

    public function testNewAllowedCountryAlertsOnlyWithMatureBaseline(): void
    {
        $user = $this->user('10.0.0.2');
        $this->matureBaseline($user);
        $this->peer('key-a', '10.0.0.2/32', '198.51.100.10');
        monitor_poll_wireguard($this->now);
        $this->peer('key-a', '10.0.0.2/32', '192.0.2.10'); // DE: allowed, but new for this user
        $findings = monitor_poll_wireguard($this->now + 3 * 3600)['findings'];

        $this->assertSame(['W1'], array_column($findings, 'rule'));
        $this->assertSame('medium', $findings[0]['severity']);
        $this->assertFalse(place_is_known((int)$user['id'], 'country', 'DE'), 'pending until nobody objects');
        places_learn_pending($this->now + 4 * 86400);
        $this->assertTrue(place_is_known((int)$user['id'], 'country', 'DE'));
    }

    public function testFlappingEndpointAndUnknownPeerAndDataVolume(): void
    {
        $user = $this->user('10.0.0.2');
        $this->matureBaseline($user);
        $rules = [];
        foreach (['198.51.100.10', '198.51.100.20', '198.51.100.10', '198.51.100.20', '198.51.100.10'] as $i => $ip) {
            $this->peer('key-a', '10.0.0.2/32', $ip);
            $rules = array_merge($rules, array_column(monitor_poll_wireguard($this->now + $i * 300)['findings'], 'rule'));
        }
        $this->assertContains('W5', $rules);

        $this->peer('key-x', '10.9.9.9/32', '198.51.100.99');
        $this->assertSame(['W7'], array_column(monitor_poll_wireguard($this->now + 2000)['findings'], 'rule'));

        $this->peer('key-a', '10.0.0.2/32', '198.51.100.10', 2 * 1024 * 1024 * 1024);
        $volume = array_column(monitor_poll_wireguard($this->now + 2100)['findings'], 'rule');
        $this->assertContains('W6', $volume);
        $this->peer('key-a', '10.0.0.2/32', '198.51.100.10', 3 * 1024 * 1024 * 1024);
        $this->assertNotContains('W6', array_column(monitor_poll_wireguard($this->now + 2200)['findings'], 'rule'), 'once per day');
    }

    public function testRouterFailureLeadsToHealthAlert(): void
    {
        run_monitor_cycle($this->now);
        $this->router->failing = true;
        $stats = run_monitor_cycle($this->now + 300);
        $this->assertSame('partial', $stats['status']);
        $this->assertSame([], monitor_health_findings($this->now + 600));
        $this->assertSame(['M1'], array_column(monitor_health_findings($this->now + 2000), 'rule'));
    }

    // --- audit log rules ---------------------------------------------------------------------------

    public function testAuditRules(): void
    {
        $user = $this->user('10.0.0.2');
        $this->user('10.0.0.1', 15, 'admin');
        monitor_audit_findings($this->now); // first call only sets the cursor
        log_event('otp_reuse_blocked', 'Attempted reused OTP', (int)$user['id'], $user['username'], $user['user_ip']);
        for ($i = 0; $i < 6; $i++) {
            log_event('login_failed', 'Wrong OTP', null, null, '10.0.0.2');
        }
        log_event('user_role_changed', 'user -> admin', (int)$user['id'], $user['username'], $user['user_ip'], ['from' => 'user', 'to' => 'admin']);
        log_event('otp_revealed', 'OTP secret revealed by admin', (int)$user['id'], $user['username'], $user['user_ip']);
        log_event('setup_token_invalid', 'Invalid setup token', null, null, '10.0.0.66');
        $findings = monitor_audit_findings($this->now);

        $byRule = [];
        foreach ($findings as $f) {
            $byRule[$f['rule']][] = $f;
        }
        $this->assertSame('high', $byRule['P2'][0]['severity']);
        $this->assertTrue($byRule['P2'][0]['notify_user']);
        $this->assertCount(1, $byRule['P1'], 'only when the threshold is reached');
        $this->assertSame((int)$user['id'], $byRule['P1'][0]['user_id']);
        $this->assertSame(['medium', 'info'], array_column($byRule['P6'], 'severity'), 'role -> admin is medium');
        $this->assertSame('high', $byRule['P8'][0]['severity']);
        $this->assertSame([], monitor_audit_findings($this->now), 'processed once');
    }

    public function testLoginRightAfterSuspiciousLocation(): void
    {
        $user = $this->user('10.0.0.2');
        monitor_audit_findings($this->now);
        $this->peer('key-a', '10.0.0.2/32', '203.0.113.50');
        monitor_poll_wireguard(time() - 120);
        log_event('login_success', 'User logged in', (int)$user['id'], $user['username'], $user['user_ip']);
        $this->assertContains('P7', array_column(monitor_audit_findings(time()), 'rule'));
    }

    public function testLoginAfterAnsweredLocationAlertJoinsThatAlert(): void
    {
        $user = $this->user('10.0.0.2');
        monitor_audit_findings($this->now);
        $this->peer('key-a', '10.0.0.2/32', '203.0.113.50');
        $ids = monitor_create_alerts(monitor_poll_wireguard(time() - 120)['findings'], time() - 120);
        alert_user_respond(fetch_alert($ids[0]), $user, 'not_me'); // the user had to log in to answer
        log_event('login_success', 'User logged in', (int)$user['id'], $user['username'], $user['user_ip']);
        $findings = monitor_audit_findings(time());
        $this->assertSame(['P7'], array_column($findings, 'rule'));
        $this->assertFalse($findings[0]['notify_user'], 'the user is not asked again');
        $this->assertSame($ids, monitor_create_alerts($findings, time()), 'joins the answered alert');
        $this->assertCount(1, $this->alerts());
        $this->assertStringContainsString('P7', fetch_alert($ids[0])['rules']);

        // confirmed place: P7 is dropped
        $other = $this->user('10.0.0.3');
        $this->peer('key-b', '10.0.0.3/32', '203.0.113.60');
        $ids = monitor_create_alerts(monitor_poll_wireguard(time() - 60)['findings'], time() - 60);
        alert_user_respond(fetch_alert($ids[0]), $other, 'me');
        log_event('login_success', 'User logged in', (int)$other['id'], $other['username'], $other['user_ip']);
        $this->assertSame([], monitor_audit_findings(time()));
    }

    public function testBehaviourRules(): void
    {
        $user = $this->user('10.0.0.2');
        save_network(null, 'Office', 1, '10.10.0.0/24');
        save_network(null, 'Datacenter', 5, '192.168.100.0/24');
        [$office, $dc] = array_map('intval', array_column(get_all_networks(), 'id'));
        $this->matureBaseline($user, $office);
        monitor_audit_findings($this->now);

        $insert = db()->prepare('INSERT INTO audit_log (user_id, username, user_ip, action, details, ip, created_at, meta) VALUES (:u, :n, :ip, :a, :d, :ip, :t, :m)');
        $night = strtotime(date('Y-m-d', $this->now) . ' 03:10:00');
        $insert->execute([':u' => $user['id'], ':n' => $user['username'], ':ip' => $user['user_ip'], ':a' => 'login_success', ':d' => '', ':t' => $night, ':m' => null]);
        for ($i = 0; $i < 5; $i++) {
            $insert->execute([':u' => $user['id'], ':n' => $user['username'], ':ip' => $user['user_ip'], ':a' => 'extended_access_granted', ':d' => 'Networks: Datacenter', ':t' => $this->now + $i * 60, ':m' => json_encode(['networks' => [$dc]])]);
        }
        $rules = array_count_values(array_column(monitor_audit_findings($this->now + 600), 'rule'));
        $this->assertSame(1, $rules['P3'] ?? 0, 'unusual hour');
        $this->assertSame(5, $rules['P4'] ?? 0, 'unknown network (deduplicated later by the cooldown)');
        $this->assertSame(1, $rules['P5'] ?? 0, 'burst of single grants');
    }

    // --- alerts and mail ---------------------------------------------------------------------------

    public function testDeduplicationBundlingAndRenotification(): void
    {
        $user = $this->user('10.0.0.2');
        $w4 = finding('W4', 'medium', (int)$user['id'], 'hosting', [], [], 'AS14061', true, null, $this->now);
        $ids = monitor_create_alerts([$w4], $this->now);
        $this->assertCount(1, $ids);
        $this->assertSame([], monitor_create_alerts([$w4], $this->now + 3600), 'same finding within the cooldown');

        db()->prepare('INSERT INTO alert_deliveries (alert_id, recipient, delivered_at) VALUES (:a, :r, :t)')->execute([':a' => $ids[0], ':r' => 'x@example.test', ':t' => $this->now]);
        $p2 = finding('P2', 'high', (int)$user['id'], 'otp', [], [], '1', true, null, $this->now + 60);
        $this->assertSame($ids, monitor_create_alerts([$p2], $this->now + 60), 'bundled into the open alert');
        $alert = fetch_alert($ids[0]);
        $this->assertSame('high', $alert['severity']);
        $this->assertSame('W4,P2', $alert['rules']);
        $this->assertSame([], alert_delivered_to($ids[0]), 'more serious: delivered again');

        $later = finding('W4', 'medium', (int)$user['id'], 'hosting', [], [], 'AS14061', true, null, $this->now + 2 * 86400);
        $this->assertCount(1, monitor_create_alerts([$later], $this->now + 2 * 86400), 'after the cooldown');
        $this->assertCount(2, $this->alerts());
    }

    public function testMediumAlertsAtMostHourlyHighAtOnce(): void
    {
        $a = $this->user('10.0.0.2');
        $b = $this->user('10.0.0.3');
        monitor_create_alerts([finding('W4', 'medium', (int)$a['id'], 'a', [], [], 'x', false, null, $this->now)], $this->now);
        $this->assertSame(1, monitor_notify($this->now)['sent']);
        monitor_create_alerts([finding('W4', 'medium', (int)$b['id'], 'b', [], [], 'x', false, null, $this->now + 600)], $this->now + 600);
        $this->assertSame(1, monitor_notify($this->now + 600)['deferred']);
        monitor_create_alerts([finding('P2', 'high', (int)$a['id'], 'otp', [], [], '9', false, null, $this->now + 700)], $this->now + 700 + 3600);
        $stats = monitor_notify($this->now + 700 + 3600);
        $this->assertSame(1, $stats['sent'], 'one mail with both pending alerts');
        $this->assertStringContainsString('2 security alerts (highest: HIGH)', end($this->mailer->sent)['subject']);
    }

    public function testDigestForLowAndInfo(): void
    {
        $user = $this->user('10.0.0.2');
        $early = strtotime(date('Y-m-d', $this->now) . ' 06:00:00');
        monitor_create_alerts([finding('P6', 'info', (int)$user['id'], 'OTP secret revealed', [], [], '1', false, null, $early)], $early);
        $this->assertSame(0, monitor_notify($early)['digest']);
        $this->assertSame(1, monitor_notify($early + 3900)['digest']);
        $this->assertStringContainsString('Daily digest', $this->mailer->sent[0]['subject']);
        $this->assertSame(0, monitor_notify($early + 7200)['digest'], 'once a day');
        $this->assertNotNull($this->alerts()[0]['notified_at']);
    }

    public function testFailedMailIsRetriedThenGivenUp(): void
    {
        $user = $this->user('10.0.0.2');
        $this->mailer->failFor['security@example.test'] = 'SMTP: connect failed';
        monitor_create_alerts([finding('P2', 'high', (int)$user['id'], 'otp', [], [], '1', false, null, $this->now)], $this->now);
        for ($i = 0; $i < NOTIFY_MAX_ATTEMPTS; $i++) {
            monitor_notify($this->now + $i * 300);
        }
        $alert = $this->alerts()[0];
        $this->assertNull($alert['notified_at']);
        $this->assertSame(NOTIFY_MAX_ATTEMPTS, (int)$alert['notify_attempts']);
        $this->assertSame('SMTP: connect failed', $alert['notify_error']);
        $this->assertSame(0, monitor_notify($this->now + 9999)['failed'], 'no further attempts');
    }

    // --- user answers ------------------------------------------------------------------------------

    public function testThatWasMeConfirmsThePlaces(): void
    {
        $user = $this->user('10.0.0.2');
        $ids = monitor_create_alerts([
            finding('W2', 'high', (int)$user['id'], 'US', ['country' => 'US', 'asn' => 14061], [], 'US', true, 'from US', $this->now),
            finding('W4', 'medium', (int)$user['id'], 'hosting', ['country' => 'US', 'asn' => 14061], [], 'AS14061', true, 'hosting', $this->now),
        ], $this->now);
        $this->assertSame(1, count(alerts_awaiting_user((int)$user['id'])));
        alert_user_respond(fetch_alert($ids[0]), $user, 'me');

        $alert = fetch_alert($ids[0]);
        $this->assertSame('me', $alert['user_response']);
        $this->assertSame('acknowledged', $alert['status']);
        $this->assertTrue(place_is_known((int)$user['id'], 'country', 'US'));
        $this->assertTrue(place_is_known((int)$user['id'], 'asn', '14061'));
        $this->assertSame([], alerts_awaiting_user((int)$user['id']));
        $this->expectException(RuntimeException::class);
        alert_user_respond($alert, $user, 'not_me'); // answered already
    }

    public function testThatWasNotMeRevokesAccessAndEscalates(): void
    {
        $user = $this->user('10.0.0.2');
        $this->user('10.0.0.3');
        $this->router->addAddressListEntry('Whitelist 10.0.0.2', '10.10.0.0/24', 'PANAG ext: Office', '01:00:00');
        $this->router->addAddressListEntry('Whitelist 10.0.0.3', '10.10.0.0/24', 'PANAG ext: Office', '01:00:00');
        $ids = monitor_create_alerts([finding('W4', 'medium', (int)$user['id'], 'hosting', ['asn' => 14061], [], 'AS', true, 'x', $this->now)], $this->now);
        db()->prepare('INSERT INTO alert_deliveries (alert_id, recipient, delivered_at) VALUES (:a, :r, :t)')->execute([':a' => $ids[0], ':r' => 'security@example.test', ':t' => $this->now]);

        alert_user_respond(fetch_alert($ids[0]), $user, 'not_me');

        $alert = fetch_alert($ids[0]);
        $this->assertSame('high', $alert['severity']);
        $this->assertStringEndsWith(',U1', $alert['rules']);
        $this->assertSame(0, (int)$alert['notify_user']);
        $this->assertSame([], alert_delivered_to($ids[0]), 'admins are mailed again');
        $this->assertSame(['Whitelist 10.0.0.3'], array_column($this->router->entries, 'list'), 'only the own access is revoked');
    }

    // --- AI ------------------------------------------------------------------------------------------

    public function testAiGetsOnlyPseudonymisedFactsAndPrivacyIsEnforced(): void
    {
        $user = $this->user('10.0.0.2');
        $ids = monitor_create_alerts([finding('W2', 'high', (int)$user['id'], 'Laptop of User 10.0.0.2 from 203.0.113.50',
            ['country' => 'US', 'asn' => 14061, 'asn_org' => 'DigitalOcean, LLC', 'asn_type' => 'hosting', 'known_countries' => ['CH'], 'peer_name' => 'Laptop', 'ip' => '203.0.113.50'],
            [], 'US', true, null, $this->now)], $this->now);
        $this->aiAnswer = self::aiOk(['severity' => 'critical']);
        $stats = monitor_ai_triage($ids, $this->now);

        $this->assertSame(1, $stats['assessed']);
        $request = $this->aiRequests[0];
        $sent = json_encode($request);
        foreach (['User 10.0.0.2', '10.0.0.2', '203.0.113', 'Laptop', 'peer_name', 'JBSWY'] as $forbidden) {
            $this->assertStringNotContainsString($forbidden, $sent, $forbidden);
        }
        $this->assertSame(['require_parameters' => true, 'data_collection' => 'deny', 'zdr' => true, 'only' => ['TestProvider'], 'allow_fallbacks' => true,
            'max_price' => ['prompt' => 2, 'completion' => 6]], $request['provider']);
        $this->assertSame('json_schema', $request['response_format']['type']);
        foreach ([['all'], ['*'], ['ALL'], ['TestProvider', 'all']] as $all) {
            $prefs = ai_provider_preferences($all);
            $this->assertArrayNotHasKey('only', $prefs, implode(',', $all) . ' allows any provider');
            $this->assertTrue($prefs['zdr'], 'zero data retention also with all');
            $this->assertSame('deny', $prefs['data_collection']);
        }
        $this->assertTrue($request['response_format']['json_schema']['strict']);
        $this->assertSame('z-ai/glm-5.3', $request['model']);
        $this->assertSame(['effort' => 'low'], $request['reasoning']);
        $features = json_decode($request['messages'][1]['content'], true);
        $this->assertMatchesRegularExpression('/^U-[0-9a-f]{8}$/', $features['subject']);
        $this->assertSame(['country' => 'US', 'known_countries' => ['CH'], 'asn' => 14061, 'asn_org' => 'DigitalOcean, LLC', 'asn_type' => 'hosting'], $features['findings'][0]['facts']);

        $this->assertSame('critical', fetch_alert($ids[0])['severity'], 'the AI may raise');
        $this->assertSame(1, ai_usage_today($this->now)['calls']);
    }

    public function testAiCannotLowerAndFailuresFallBack(): void
    {
        $user = $this->user('10.0.0.2');
        $make = fn(string $key) => monitor_create_alerts([finding('P2', 'high', (int)$user['id'], 'otp', [], [], $key, false, null, $this->now)], $this->now)[0];

        $this->aiAnswer = self::aiOk(['severity' => 'low', 'likely_benign' => true]);
        $id = $make('a');
        monitor_ai_triage([$id], $this->now);
        $this->assertSame('high', fetch_alert($id)['severity']);
        $this->assertTrue(alert_ai(fetch_alert($id))['likely_benign']);

        foreach ([
            ['status' => 502, 'body' => ['error' => ['message' => 'Provider returned error']], 'error' => null],
            self::aiOk([], 'length'),
            ['status' => 200, 'error' => null, 'body' => ['choices' => [['finish_reason' => 'stop', 'message' => ['content' => '{"severity":"weird"}']]]]],
        ] as $i => $answer) {
            db()->exec('UPDATE alerts SET status = \'resolved\'');
            $this->aiAnswer = $answer;
            $id = $make('fail' . $i);
            $stats = monitor_ai_triage([$id], $this->now);
            $this->assertSame(1, $stats['failed'], 'case ' . $i);
            $this->assertNull(fetch_alert($id)['ai']);
            $this->assertSame('high', fetch_alert($id)['severity']);
        }
        monitor_state_set('ai.usage.' . date('Y-m-d', $this->now), ['calls' => MONITOR_AI_MAX_CALLS_PER_DAY, 'failures' => 0, 'prompt_tokens' => 0, 'completion_tokens' => 0]);
        db()->exec('UPDATE alerts SET status = \'resolved\'');
        $stats = monitor_ai_triage([$make('limit')], $this->now);
        $this->assertStringContainsString('Daily limit', (string)$stats['skipped']);
    }

    // --- findings of the second review -------------------------------------------------------------

    public function testMissingCountryDatabaseDisablesLocationRules(): void
    {
        set_geoip(new MmdbGeoLookup('/nonexistent/country.mmdb', '/nonexistent/asn.mmdb'));
        $user = $this->user('10.0.0.2');
        $this->peer('key-a', '10.0.0.2/32', '203.0.113.50');
        $this->assertSame([], monitor_poll_wireguard($this->now)['findings'], 'no W2 flood without a database');
        $this->assertFalse(place_is_known((int)$user['id'], 'country', '??'));
    }

    public function testOnlyHostRoutesMapPeersToUsers(): void
    {
        $users = [['id' => 1, 'user_ip' => '10.8.0.2'], ['id' => 2, 'user_ip' => '10.8.0.3']];
        $this->assertNull(wg_peer_user(['allowed-address' => '10.8.0.0/24'], $users), 'site-to-site range');
        $this->assertSame(2, wg_peer_user(['allowed-address' => '192.168.5.0/24,10.8.0.3/32'], $users)['id']);
        $this->assertSame(1, wg_peer_user(['allowed-address' => '10.8.0.2'], $users)['id']);
    }

    public function testLargeByteCountersAndUtf8(): void
    {
        $this->user('10.0.0.2');
        $this->peer('key-a', '10.0.0.2/32', '198.51.100.10', 0);
        monitor_poll_wireguard($this->now);
        $this->router->peers[0]['rx'] = '5000000000'; // > 2^32, would saturate as int on 32-bit PHP
        monitor_poll_wireguard($this->now + 300);
        $this->assertEqualsWithDelta(5e9, (float)db()->query('SELECT bytes FROM wg_traffic_days')->fetchColumn(), 1);

        $this->assertSame('Zürich', mb_substr_safe('Zürich AG', 6), 'cuts characters, not bytes');
        $this->assertSame('ab', mb_substr_safe("a\x00b", 10), 'control characters');
        $this->assertSame('Zrich', mb_substr_safe("Z\xFCrich", 10), 'invalid UTF-8 is reduced to ASCII');
    }

    public function testChangedAlertsAreMailedAgainButAnsweredUsersAreNotAsked(): void
    {
        $user = $this->user('10.0.0.2', 5, 'user', 'u@example.test');
        $ids = monitor_create_alerts([finding('P1', 'medium', (int)$user['id'], 'fails', [], [], 'a', false, null, $this->now)], $this->now);
        monitor_notify($this->now);
        $this->assertSame(['security@example.test'], $this->mailer->recipients());

        // same severity, new kind of finding that asks the user: mailed again, now also to the user
        monitor_create_alerts([finding('W4', 'medium', (int)$user['id'], 'hosting', [], [], 'b', true, 'hosting', $this->now + 60)], $this->now + 60);
        monitor_notify($this->now + 4000);
        $this->assertSame(['security@example.test', 'security@example.test', 'u@example.test'], $this->mailer->recipients());

        // the user answered via the banner before a later mail: admins yes, user no
        db()->prepare("UPDATE alerts SET user_response = 'me' WHERE id = :id")->execute([':id' => $ids[0]]);
        alert_reset_delivery($ids[0]);
        monitor_notify($this->now + 8000);
        $this->assertSame('security@example.test', end($this->mailer->sent)['to']);
        $this->assertCount(4, $this->mailer->sent);
    }

    public function testNotMeOnAnOldAlertIsStillMailed(): void
    {
        $user = $this->user('10.0.0.2');
        $old = $this->now - 8 * 86400;
        $ids = monitor_create_alerts([finding('W4', 'medium', (int)$user['id'], 'hosting', [], [], 'x', true, 'x', $old)], $old);
        db()->prepare('UPDATE alerts SET notified_at = :t WHERE id = :id')->execute([':t' => $old, ':id' => $ids[0]]);
        alert_user_respond(fetch_alert($ids[0]), $user, 'not_me');
        $this->assertSame(1, monitor_notify(time())['sent']);
    }

    public function testAnswersOnlyWhileOpenAndAsked(): void
    {
        $user = $this->user('10.0.0.2');
        $ids = monitor_create_alerts([finding('W2', 'high', (int)$user['id'], 'US', ['country' => 'US'], [], 'US', true, 'US', $this->now)], $this->now);
        alert_set_status(fetch_alert($ids[0]), 'confirmed', $this->user('10.0.0.1', 15, 'admin'), 'incident');
        $this->assertFalse(alert_answerable(fetch_alert($ids[0]), $user));
        try {
            alert_user_respond(fetch_alert($ids[0]), $user, 'me');
            $this->fail('closed alerts cannot be answered');
        } catch (RuntimeException $e) {
            $this->assertFalse(place_is_known((int)$user['id'], 'country', 'US'));
        }
        $silent = monitor_create_alerts([finding('P1', 'medium', (int)$user['id'], 'fails', [], [], 'p', false, null, $this->now)], $this->now);
        $this->assertFalse(alert_answerable(fetch_alert($silent[0]), $user), 'the user was never asked');

        place_remember((int)$user['id'], 'country', 'FR', 'pending', $this->now);
        alert_set_status(fetch_alert($silent[0]), 'confirmed', $this->user('10.0.0.5', 15, 'admin'), 'incident');
        places_learn_pending($this->now + 10 * 86400);
        $this->assertFalse(place_is_known((int)$user['id'], 'country', 'FR'), 'no learning from a confirmed incident');
    }

    public function testLoginBeforeTheEndpointWasPolled(): void
    {
        $user = $this->user('10.0.0.2');
        monitor_audit_findings($this->now);
        log_event('login_success', 'User logged in', (int)$user['id'], $user['username'], $user['user_ip']);
        $this->peer('key-a', '10.0.0.2/32', '203.0.113.50');
        monitor_poll_wireguard(time() + 240); // the WireGuard connect is seen at the next poll
        $this->assertContains('P7', array_column(monitor_audit_findings(time() + 240), 'rule'));
    }

    public function testAiResultNeverLowersAConcurrentChange(): void
    {
        $user = $this->user('10.0.0.2');
        $ids = monitor_create_alerts([finding('W4', 'medium', (int)$user['id'], 'hosting', [], [], 'x', false, null, $this->now)], $this->now);
        set_ai_transport(function (array $body) use ($ids): array {
            db()->prepare("UPDATE alerts SET severity = 'critical' WHERE id = :id")->execute([':id' => $ids[0]]); // e.g. "not me" meanwhile
            return self::aiOk(['severity' => 'high']);
        });
        monitor_ai_triage($ids, $this->now);
        $this->assertSame('critical', fetch_alert($ids[0])['severity']);
    }

    // --- helpers, GeoIP files, retention, request check --------------------------------------------

    public function testHelpers(): void
    {
        $this->assertSame(72, parse_wg_handshake_age('1m12s'));
        $this->assertSame(90, parse_wg_handshake_age('90'));
        $this->assertNull(parse_wg_handshake_age(''));
        $this->assertSame('198.51.100.1', wg_peer_endpoint(['current-endpoint-address' => '198.51.100.1', 'endpoint-address' => '192.0.2.1']));
        $this->assertSame('2001:db8::1', wg_peer_endpoint(['current-endpoint-address' => '[2001:db8::1]']));
        $this->assertSame('', wg_peer_endpoint(['current-endpoint-address' => '']));
        foreach (['10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.1.1', 'fe80::1', '::1', 'fd00::1', '::ffff:10.0.0.1'] as $ip) {
            $this->assertFalse(geoip_is_public_ip($ip), $ip);
        }
        foreach (['203.0.113.5', '8.8.8.8', '2001:db8::1', '::ffff:8.8.8.8'] as $ip) {
            $this->assertTrue(geoip_is_public_ip($ip), $ip);
        }
        $this->assertSame('unit-monitor-token', monitor_token(), 'MONITOR_TOKEN wins over the generated file');
        $this->assertTrue(monitor_request_allowed('172.17.0.1', 'unit-monitor-token'));
        $this->assertFalse(monitor_request_allowed('172.17.0.9', 'unit-monitor-token'), 'wrong source');
        $this->assertFalse(monitor_request_allowed('172.17.0.1', 'wrong'), 'wrong token');
        $this->assertSame('high', severity_max('medium', 'high'));
        $this->assertSame('critical', severity_raise('critical'));
        $this->assertTrue(is_hosting_asn(14061));
        $this->assertFalse(is_hosting_asn(3303));
    }

    public function testMmdbFixtureWithTheRealReader(): void
    {
        $dir = sys_get_temp_dir() . '/panag-geoip-' . getmypid();
        @mkdir($dir);
        $country = new MmdbWriter('DBIP-Country-Lite');
        $asn = new MmdbWriter('DBIP-ASN-Lite (compat=GeoLite2-ASN)');
        foreach ([['198.51.100.0/24', 'CH', 3303, 'Swisscom (Schweiz) AG'], ['203.0.113.0/24', 'US', 14061, 'DigitalOcean, LLC'], ['2001:db8::/32', 'CH', 3303, 'Swisscom (Schweiz) AG']] as [$cidr, $code, $number, $org]) {
            $country->insert($cidr, ['country' => ['iso_code' => $code, 'names' => ['en' => $code]]]);
            $asn->insert($cidr, ['autonomous_system_number' => $number, 'autonomous_system_organization' => $org]);
        }
        $country->write($dir . '/country.mmdb');
        $asn->write($dir . '/asn.mmdb');

        $lookup = new MmdbGeoLookup($dir . '/country.mmdb', $dir . '/asn.mmdb');
        $this->assertSame(['country' => 'CH', 'asn' => 3303, 'asn_org' => 'Swisscom (Schweiz) AG', 'available' => true], $lookup->lookup('198.51.100.77'));
        $this->assertSame(['country' => 'US', 'asn' => 14061, 'asn_org' => 'DigitalOcean, LLC', 'available' => true], $lookup->lookup('203.0.113.9'));
        $this->assertSame('CH', $lookup->lookup('2001:db8::5')['country']);
        $this->assertSame(['country' => null, 'asn' => null, 'asn_org' => null, 'available' => true], $lookup->lookup('8.8.8.8'), 'public but unknown');
        $this->assertNull($lookup->lookup('10.0.0.1'), 'private');

        $this->assertNull(geoip_validate_file($dir . '/country.mmdb', 'country'));
        $this->assertNull(geoip_validate_file($dir . '/asn.mmdb', 'asn'));
        $this->assertStringContainsString('not an ASN database', (string)geoip_validate_file($dir . '/country.mmdb', 'asn'));
        file_put_contents($dir . '/junk.mmdb', 'junk');
        $this->assertStringContainsString('Not a valid MMDB', (string)geoip_validate_file($dir . '/junk.mmdb', 'country'));
        array_map('unlink', glob($dir . '/*') ?: []);
        rmdir($dir);
    }

    public function testRetention(): void
    {
        $user = $this->user('10.0.0.2');
        $this->peer('key-a', '10.0.0.2/32', '198.51.100.10');
        monitor_poll_wireguard($this->now - 40 * 86400);
        monitor_create_alerts([finding('P2', 'high', (int)$user['id'], 'old', [], [], 'old', false, null, $this->now - 400 * 86400)], $this->now - 400 * 86400);
        monitor_retention($this->now);
        $row = db()->query('SELECT ip, country FROM wg_endpoints')->fetch(PDO::FETCH_ASSOC);
        $this->assertNull($row['ip'], 'public IP removed after MONITOR_IP_RETENTION_DAYS');
        $this->assertSame(0, (int)db()->query('SELECT COUNT(*) FROM wg_peers')->fetchColumn(), 'peer gone from the router, its last endpoint too');
        $this->assertSame('CH', $row['country']);
        $this->assertSame([], $this->alerts());
    }

    public function testRuleReferenceCoversEveryRule(): void
    {
        $reference = monitor_rule_reference();
        $this->assertSame(array_keys(MONITOR_RULES), array_keys($reference));
        foreach ($reference as $code => $rule) {
            $this->assertSame(MONITOR_RULES[$code], $rule['name']);
            $this->assertNotSame('', $rule['when'], $code);
            $this->assertNotSame([], $rule['severity'], $code);
            foreach ($rule['severity'] as $severity) {
                $this->assertContains($severity, ['info', 'low', 'medium', 'high'], $code);
            }
        }
        $this->assertStringContainsString('CH', $reference['W2']['when'], 'current allowlist filled in');
        $this->assertTrue($reference['W2']['asks_user']);
        $this->assertFalse($reference['P8']['asks_user']);
    }
}
