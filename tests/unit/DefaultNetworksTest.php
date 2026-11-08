<?php
use PHPUnit\Framework\TestCase;

final class DefaultNetworksTest extends TestCase
{
    protected function setUp(): void
    {
        $pdo = db();
        foreach (['user_to_network', 'otp_used', 'networks', 'users', 'audit_log', 'login_attempts'] as $table) {
            $pdo->exec("DELETE FROM {$table}");
        }
        set_router(new FakeRouterClient());
    }

    protected function tearDown(): void
    {
        set_router(null);
    }

    private function user(string $ip, int $level, string $role = 'user'): array
    {
        save_user(null, 'User ' . $ip, $ip, 'JBSWY3DPEHPK3PXP', $role, $level);
        return fetch_user_by_user_ip($ip);
    }

    private function network(string $name, int $level, string $address = '10.0.0.0/24', bool $sensitive = false): int
    {
        save_network(null, $name, $level, $address, $sensitive);
        return (int)db()->query('SELECT MAX(id) FROM networks')->fetchColumn();
    }

    public function testSensitiveNetworksAreNeverDefaults(): void
    {
        $admin = $this->user('10.0.0.1', 15, 'admin');
        $user = $this->user('10.0.0.2', 10);
        $office = $this->network('Office', 1);
        $core = $this->network('Core', 5, '10.255.0.0/28', true);

        $only = change_default_networks($admin, $user, [$core], true);
        $this->assertSame(422, $only['status']);
        $this->assertStringContainsString('Core is a sensitive network', $only['message']);

        $mixed = change_default_networks($admin, $user, [$office, $core], true);
        $this->assertSame([$office], $mixed['changed']);
        $this->assertSame([$core], $mixed['rejected']);
        $this->assertSame([$office], get_user_default_network_ids((int)$user['id']));

        set_user_default_networks((int)$user['id'], [$office, $core]);
        $this->assertSame([$office], get_user_default_network_ids((int)$user['id']), 'also the bulk setter skips them');

        $this->assertTrue(network_can_be_default($user, fetch_network_by_id($office)));
        $this->assertFalse(network_can_be_default($user, fetch_network_by_id($core)));
        $this->assertTrue(change_default_networks($admin, $user, [$core], false)['status'] === 200, 'removing is always allowed');
    }

    public function testMarkingANetworkSensitiveRemovesItFromAllDefaults(): void
    {
        $admin = $this->user('10.0.0.1', 15, 'admin');
        $a = $this->user('10.0.0.2', 10);
        $b = $this->user('10.0.0.3', 10);
        $vpn = $this->network('VPN', 1);
        change_default_networks($admin, $a, [$vpn], true);
        change_default_networks($admin, $b, [$vpn], true);

        $this->assertSame(0, save_network($vpn, 'VPN', 1, '10.0.0.0/24'), 'not sensitive: nothing removed');
        $this->assertSame(2, save_network($vpn, 'VPN', 1, '10.0.0.0/24', true));
        $this->assertSame([], get_user_default_network_ids((int)$a['id']));
        $this->assertSame([], get_user_default_network_ids((int)$b['id']));
        $this->assertTrue(network_is_sensitive(fetch_network_by_id($vpn)));

        save_network($vpn, 'VPN', 1, '10.0.0.0/24', false);
        $this->assertFalse(network_is_sensitive(fetch_network_by_id($vpn)), 'the flag can be removed again');
    }

    public function testNetworkBackupKeepsTheSensitiveFlag(): void
    {
        require_once __DIR__ . '/../../src/backup.php';
        $this->network('Office', 1);
        $this->network('Core', 5, '10.255.0.0/28', true);
        $json = export_networks_json();
        $this->assertSame([false, true], array_column(json_decode($json, true), 'sensitive'));

        $this->assertSame(2, import_networks_json($json));
        $flags = db()->query('SELECT name, sensitive FROM networks ORDER BY name')->fetchAll(PDO::FETCH_KEY_PAIR);
        $this->assertSame(['Core' => 1, 'Office' => 0], array_map('intval', $flags));
        $this->assertSame(1, import_networks_json((string)json_encode([['name' => 'Old', 'address' => '10.1.0.0/24', 'accesslevel' => 1]])), 'old exports without the flag still import');
    }

    public function testWhoMayEditWhoseDefaults(): void
    {
        $admin = $this->user('10.0.0.1', 15, 'admin');
        $super = $this->user('10.0.0.3', 8, 'superuser');
        $user = $this->user('10.0.0.2', 5);

        $this->assertTrue(can_edit_default_networks_of($admin, $user));
        $this->assertTrue(can_edit_default_networks_of($admin, $admin));
        $this->assertTrue(can_edit_default_networks_of($super, $super));
        $this->assertFalse(can_edit_default_networks_of($super, $user), 'superusers manage only their own');
        $this->assertFalse(can_edit_default_networks_of($user, $user), 'users cannot pick their own');
        $this->assertFalse(can_edit_default_networks_of(null, $user));
    }

    public function testSuperuserCanOnlyAddNetworksWithinOwnLevel(): void
    {
        $super = $this->user('10.0.0.3', 8, 'superuser');
        $low = $this->network('Office', 1);
        $high = $this->network('Core', 12);

        $result = change_default_networks($super, $super, [$low, $high, 999], true);

        $this->assertSame(200, $result['status']);
        $this->assertSame([$low], $result['changed']);
        $this->assertEqualsCanonicalizing([$high, 999], $result['rejected']);
        $this->assertSame([$low], get_user_default_network_ids((int)$super['id']));
        $this->assertStringContainsString('Office added to your default networks', $result['message']);

        $only = change_default_networks($super, $super, [$high], true);
        $this->assertSame(422, $only['status']);
        $this->assertStringContainsString('Core requires level 12', $only['message']);
    }

    public function testOthersAreForbiddenForNonAdmins(): void
    {
        $super = $this->user('10.0.0.3', 8, 'superuser');
        $user = $this->user('10.0.0.2', 5);
        $net = $this->network('Office', 1);

        $this->assertSame(403, change_default_networks($super, $user, [$net], true)['status']);
        $this->assertSame(403, change_default_networks($user, $user, [$net], true)['status']);
        $this->assertSame([], get_user_default_network_ids((int)$user['id']));
    }

    public function testAdminIsBoundByTheTargetsLevelToo(): void
    {
        $admin = $this->user('10.0.0.1', 15, 'admin');
        $user = $this->user('10.0.0.2', 5);
        $ok = $this->network('Office', 5);
        $tooHigh = $this->network('Datacenter', 8);

        $this->assertSame(200, change_default_networks($admin, $user, [$ok], true)['status']);
        $this->assertSame(422, change_default_networks($admin, $user, [$tooHigh], true)['status']);
        $this->assertSame([$ok], get_user_default_network_ids((int)$user['id']));

        $log = db()->query("SELECT * FROM audit_log WHERE action = 'default_network_added'")->fetch(PDO::FETCH_ASSOC);
        $this->assertSame('10.0.0.2', $log['user_ip']);
        $this->assertStringContainsString('Office (10.0.0.0/24) by User 10.0.0.1', $log['details']);
    }

    public function testIneligibleDefaultsAreFlaggedAndCanAlwaysBeRemoved(): void
    {
        $admin = $this->user('10.0.0.1', 15, 'admin');
        $user = $this->user('10.0.0.2', 8);
        $dc = $this->network('Datacenter', 8);
        change_default_networks($admin, $user, [$dc], true);

        update_user_account((int)$user['id'], $user['username'], $user['user_ip'], 'user', 5); // level lowered
        $user = fetch_user_by_id((int)$user['id']);
        $this->assertSame(['Datacenter'], array_column(ineligible_default_networks($user), 'name'));
        $row = array_values(array_filter(users_with_default_counts(), fn($u) => (int)$u['id'] === (int)$user['id']))[0];
        $this->assertSame(1, (int)$row['default_count']);
        $this->assertSame(1, (int)$row['invalid_default_count']);

        $removed = change_default_networks($admin, $user, [$dc], false);
        $this->assertSame(200, $removed['status']);
        $this->assertSame([], get_user_default_network_ids((int)$user['id']));
    }

    public function testUnchangedRequestsAreNoOps(): void
    {
        $super = $this->user('10.0.0.3', 8, 'superuser');
        $net = $this->network('Office', 1);
        change_default_networks($super, $super, [$net], true);
        $before = (int)db()->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();

        $again = change_default_networks($super, $super, [$net], true);

        $this->assertSame([], $again['changed']);
        $this->assertSame('Nothing changed.', $again['message']);
        $this->assertSame($before, (int)db()->query('SELECT COUNT(*) FROM audit_log')->fetchColumn());
        $this->assertSame([$net => 1], default_network_counts());
    }

    public function testPaletteOffersOnlyEligibleNetworksAndRoleCommands(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $admin = $this->user('10.0.0.1', 15, 'admin');
        $office = $this->network('Office', 1, '10.10.0.0/24');
        $this->network('Datacenter', 8, '192.168.100.0/24');
        change_default_networks($admin, $user, [$office], true);
        grant_networks($user, [fetch_network_by_id($office)], 'default');

        $data = palette_data($user);
        $this->assertSame(['Office'], array_column($data['networks'], 'name'));
        $this->assertTrue($data['networks'][0]['is_default']);
        $this->assertSame('10.10.0.0/24', $data['entries'][0]['address']);
        $this->assertSame([], $data['users']);
        $ids = array_column($data['commands'], 'id');
        $this->assertContains('grant-default', $ids);
        $this->assertNotContains('go-users', $ids);
        $this->assertSame(900, $data['durations']['extended']);

        $adminData = palette_data($admin);
        $this->assertCount(2, $adminData['networks']);
        $this->assertContains('go-users', array_column($adminData['commands'], 'id'));
        $this->assertNotContains('grant-default', array_column($adminData['commands'], 'id'), 'admin has no defaults');
        $this->assertEqualsCanonicalizing(['10.0.0.1', '10.0.0.2'], array_column($adminData['users'], 'ip'));
    }
}
