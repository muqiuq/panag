<?php
use PHPUnit\Framework\TestCase;

/** Detection rule settings (admin/rules.php): on/off, severity, thresholds; defaults from the environment. */
final class RuleSettingsTest extends TestCase
{
    private array $admin;

    protected function setUp(): void
    {
        foreach (['settings', 'audit_log', 'users'] as $table) {
            db()->exec("DELETE FROM {$table}");
        }
        rule_settings_reload();
        save_user(null, 'Rule Admin', '10.0.0.1', 'JBSWY3DPEHPK3PXP', 'admin', 15);
        $this->admin = fetch_user_by_user_ip('10.0.0.1');
    }

    protected function tearDown(): void
    {
        db()->exec('DELETE FROM settings');
        rule_settings_reload();
    }

    /** The form as admin/rules.php submits it: every rule on, params as displayed. */
    private function form(array $changes = []): array
    {
        $form = ['enabled' => [], 'severity' => [], 'params' => []];
        foreach (array_keys(MONITOR_RULES) as $code) {
            $form['enabled'][$code] = '1';
            $form['severity'][$code] = '';
        }
        foreach (array_keys(RULE_PARAMS) as $name) {
            $form['params'][$name] = rule_param_display($name, rule_param($name));
        }
        return array_replace_recursive($form, $changes);
    }

    public function testDefaultsComeFromTheEnvironmentOrAreBuiltIn(): void
    {
        $this->assertSame(MONITOR_FAILED_LOGINS, rule_param('failed_logins'));
        $this->assertSame(MONITOR_ALLOWED_COUNTRIES, rule_param('allowed_countries'));
        $this->assertSame(4, rule_param('switch_count'));
        $this->assertSame(1800, rule_param('router_down'));
        $this->assertSame('default', rule_param_source('switch_count'));
        $this->assertTrue(rule_enabled('W4'));
        $this->assertNull(rule_severity('W7'));
    }

    public function testTheUnchangedFormStoresNothing(): void
    {
        $result = save_rule_settings($this->form(), $this->admin);
        $this->assertTrue($result['ok']);
        $this->assertSame([], $result['changes']);
        $this->assertSame([], rule_settings()['params']);
        $this->assertSame(0, (int)db()->query("SELECT COUNT(*) FROM audit_log WHERE action = 'monitor_rules_changed'")->fetchColumn());
    }

    public function testChangesAreStoredAndLogged(): void
    {
        $form = $this->form([
            'severity' => ['W7' => 'low'],
            'params' => ['failed_logins' => '3', 'switch_window' => '45m', 'allowed_countries' => 'ch, de;at', 'hosting_asns' => 'AS64512 64513'],
        ]);
        unset($form['enabled']['W4']); // unchecked switch
        $result = save_rule_settings($form, $this->admin);

        $this->assertTrue($result['ok'], implode(' ', $result['errors']));
        $this->assertFalse(rule_enabled('W4'));
        $this->assertSame('low', rule_severity('W7'));
        $this->assertSame(3, rule_param('failed_logins'));
        $this->assertSame(2700, rule_param('switch_window'));
        $this->assertSame(['CH', 'DE', 'AT'], rule_param('allowed_countries'));
        $this->assertSame(['64512', '64513'], rule_param('hosting_asns'));
        $this->assertSame('web', rule_param_source('failed_logins'));
        $this->assertEqualsCanonicalizing(['failed_logins', 'switch_window', 'allowed_countries', 'hosting_asns'], array_keys(rule_settings()['params']));
        $this->assertContains('W4 off', $result['changes']);
        $this->assertContains('failed_logins 3', $result['changes']);
        $log = db()->query("SELECT details FROM audit_log WHERE action = 'monitor_rules_changed'")->fetchColumn();
        $this->assertStringContainsString('W4 off', (string)$log);
        $this->assertStringEndsWith('by Rule Admin', (string)$log);

        // survives a new request (cache) and stays when only some params are submitted
        rule_settings_reload();
        $this->assertSame(3, rule_param('failed_logins'));
        $this->assertTrue(save_rule_settings(['enabled' => array_fill_keys(array_keys(MONITOR_RULES), '1'), 'params' => ['switch_count' => '6']], $this->admin)['ok']);
        $this->assertSame(3, rule_param('failed_logins'), 'not submitted: kept');
        $this->assertSame(6, rule_param('switch_count'));
        $this->assertTrue(rule_enabled('W4'));

        reset_rule_settings($this->admin);
        $this->assertSame(MONITOR_FAILED_LOGINS, rule_param('failed_logins'));
        $this->assertSame(4, rule_param('switch_count'));
    }

    public function testInvalidInputStoresNothing(): void
    {
        $result = save_rule_settings($this->form([
            'severity' => ['W1' => 'apocalyptic'],
            'params' => ['failed_logins' => '1', 'allowed_countries' => 'Switzerland', 'hosting_asns' => 'ASX', 'router_down' => 'soon'],
        ]), $this->admin);
        $this->assertFalse($result['ok']);
        $this->assertCount(5, $result['errors']);
        $this->assertStringContainsString('Failed logins (P1): a whole number from 2 to 1000', implode("\n", $result['errors']));
        $this->assertSame([], rule_settings()['params']);
        $this->assertNull(rule_severity('W1'));
    }

    public function testTheUsersOwnReportCannotBeSwitchedOff(): void
    {
        $form = $this->form();
        unset($form['enabled']['U1']);
        save_rule_settings($form, $this->admin);
        $this->assertTrue(rule_enabled('U1'));
    }

    public function testSettingsAreAppliedToFindingsAndThresholds(): void
    {
        $form = $this->form(['severity' => ['W7' => 'low'], 'params' => ['failed_logins' => '3', 'router_down' => '15m']]);
        unset($form['enabled']['W4']);
        save_rule_settings($form, $this->admin);

        $now = strtotime('2026-11-07 10:00:00');
        $applied = rules_apply([
            finding('W4', 'medium', null, 'hosting', [], [], 'a', false, null, $now),
            finding('W7', 'info', null, 'unknown peer', [], [], 'b', false, null, $now),
            finding('P1', 'medium', null, 'fails', [], [], 'c', false, null, $now),
        ]);
        $this->assertSame([['W7', 'low'], ['P1', 'medium']], array_map(fn($f) => [$f['rule'], $f['severity']], $applied));

        // P1 now fires at the third failed login
        monitor_audit_findings($now); // sets the cursor
        for ($i = 0; $i < 3; $i++) {
            log_event('login_failed', 'Wrong OTP', null, null, '10.0.0.66');
        }
        $p1 = array_values(array_filter(monitor_audit_findings($now), fn($f) => $f['rule'] === 'P1'));
        $this->assertCount(1, $p1);
        $this->assertStringContainsString('3 failed PANAG logins', $p1[0]['text']);

        // M1 after 15 instead of 30 minutes
        monitor_state_set('monitor.last_poll_ok_at', $now - 16 * 60);
        $this->assertSame(['M1'], array_column(monitor_health_findings($now), 'rule'));

        // the reference texts show the effective values
        $reference = monitor_rule_reference();
        $this->assertStringContainsString('3 failed PANAG logins', $reference['P1']['when']);
        $this->assertFalse($reference['W4']['enabled']);
        $this->assertSame('low', $reference['W7']['severity_override']);
    }
}
