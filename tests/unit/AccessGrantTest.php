<?php
use PHPUnit\Framework\TestCase;

final class AccessGrantTest extends TestCase
{
    private FakeRouterClient $router;

    protected function setUp(): void
    {
        $pdo = db();
        foreach (['user_to_network', 'otp_used', 'networks', 'users', 'audit_log', 'login_attempts'] as $table) {
            $pdo->exec("DELETE FROM {$table}");
        }
        $this->router = new FakeRouterClient();
        set_router($this->router);
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

    private function network(string $name, int $level, string $address): array
    {
        save_network(null, $name, $level, $address);
        foreach (get_all_networks() as $n) {
            if ($n['name'] === $name) {
                return $n;
            }
        }
        $this->fail('network not created');
    }

    public function testGrantAddsEntriesOnlyForEligibleNetworks(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $low = $this->network('Office', 1, '10.10.0.0/24');
        $high = $this->network('Core', 9, '10.255.0.0/28');

        $results = grant_networks($user, [$low, $high], 'default');

        $this->assertTrue($results[0]['success']);
        $this->assertSame('added', $results[0]['action']);
        $this->assertFalse($results[1]['success']);
        $this->assertSame('Insufficient access level', $results[1]['message']);
        $this->assertCount(1, $this->router->entries);
        $this->assertSame('Whitelist 10.0.0.2', $this->router->entries[0]['list']);
        $this->assertSame('10.10.0.0/24', $this->router->entries[0]['address']);
        $this->assertSame('PANAG default: Office', $this->router->entries[0]['comment']);
        $this->assertSame('01:00:00', $this->router->entries[0]['timeout']);
    }

    public function testGrantUsesTheUsersOwnDurations(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $this->assertSame([], update_user_durations($user, 2 * 3600, 30 * 60));
        $user = fetch_user_by_id((int)$user['id']);
        $a = $this->network('Office', 1, '10.10.0.0/24');
        $b = $this->network('VPN', 1, '172.16.0.0/24');

        grant_networks($user, [$a], 'default');
        grant_networks($user, [$b], 'extended');

        $this->assertSame('02:00:00', $this->router->entries[0]['timeout']);
        $this->assertSame('00:30:00', $this->router->entries[1]['timeout']);
        $this->assertSame('PANAG ext: VPN', $this->router->entries[1]['comment']);
    }

    public function testInvalidDurationsAreRejected(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $this->assertCount(1, update_user_durations($user, 15 * 3600, 900));        // default > 14 h
        $this->assertCount(1, update_user_durations($user, 3600, 13 * 3600));       // extended > 12 h
        $this->assertCount(2, update_user_durations($user, 10 * 60, null));         // < 15 min, invalid
        $this->assertSame(3600, (int)fetch_user_by_id((int)$user['id'])['default_duration_sec']);
    }

    public function testRegrantExtendsButNeverShortens(): void
    {
        $user = $this->user('10.0.0.2', 5);
        update_user_durations($user, 10 * 3600, 15 * 60);
        $user = fetch_user_by_id((int)$user['id']);
        $net = $this->network('Office', 1, '10.10.0.0/24');

        grant_networks($user, [$net], 'default');                      // 10 h
        $results = grant_networks($user, [$net], 'extended');           // 15 min must not shorten it
        $this->assertSame('unchanged', $results[0]['action']);
        $this->assertSame('10:00:00', $this->router->entries[0]['timeout']);

        $this->router->entries[0]['timeout'] = '5m';                    // almost expired
        $results = grant_networks($user, [$net], 'extended');
        $this->assertSame('extended', $results[0]['action']);
        $this->assertSame('00:15:00', $this->router->entries[0]['timeout']);
        $this->assertCount(1, $this->router->entries);
    }

    public function testPermanentEntriesAreLeftAlone(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $net = $this->network('Host', 1, '10.10.0.5/32');
        // RouterOS shows single hosts without /32 and permanent entries without timeout.
        $this->router->entries[] = ['.id' => '*99', 'list' => 'Whitelist 10.0.0.2', 'address' => '10.10.0.5', 'comment' => 'manual'];
        $results = grant_networks($user, [$net], 'extended');
        $this->assertSame('Permanent entry', $results[0]['message']);
        $this->assertCount(1, $this->router->entries);
    }

    public function testRevokeAndExtendSingleOwnEntry(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $other = $this->user('10.0.0.3', 5);
        $net = $this->network('Office', 1, '10.10.0.0/24');
        grant_networks($user, [$net], 'extended');
        grant_networks($other, [$net], 'extended');
        $mine = $this->router->entries[0]['.id'];
        $theirs = $this->router->entries[1]['.id'];

        $this->assertFalse(revoke_own_entry($user, $theirs)['success'], 'must not touch other users entries');
        $this->router->entries[0]['timeout'] = '1m';
        $this->assertTrue(extend_own_entry($user, $mine)['success']);
        $this->assertSame('00:15:00', $this->router->entries[0]['timeout']);

        $this->assertTrue(revoke_own_entry($user, $mine)['success']);
        $this->assertCount(1, $this->router->entries);
        $this->assertSame($theirs, $this->router->entries[0]['.id']);
    }

    public function testCurrentAccessView(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $net = $this->network('Office', 1, '10.10.0.0/24');
        grant_networks($user, [$net], 'default');
        $view = current_access_view($user);
        $this->assertSame('Office', $view[0]['network']);
        $this->assertSame('default', $view[0]['kind']);
        $this->assertSame(3600, $view[0]['remaining_sec']);
        $this->assertSame('1 h left', $view[0]['remaining']);
    }

    public function testRevokeRemovesOnlyOwnList(): void
    {
        $a = $this->user('10.0.0.2', 5);
        $b = $this->user('10.0.0.3', 5);
        $net = $this->network('Office', 1, '10.10.0.0/24');
        grant_networks($a, [$net], 'default');
        grant_networks($b, [$net], 'default');

        $result = remove_address_list_entries('10.0.0.2');

        $this->assertTrue($result['success']);
        $this->assertSame(1, $result['deleted']);
        $this->assertCount(1, $this->router->entries);
        $this->assertSame('Whitelist 10.0.0.3', $this->router->entries[0]['list']);
    }

    public function testRouterFailureIsReported(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $net = $this->network('Office', 1, '10.10.0.0/24');
        $this->router->failing = true;
        $results = grant_networks($user, [$net], 'default');
        $this->assertFalse($results[0]['success']);
        $this->assertSame(500, $results[0]['status']);
        $this->assertSame('Some networks failed. API codes: 500', grant_summary($results, 'ok', 'Some networks failed.')['message']);
    }

    public function testDeletingUserCascadesDefaultNetworks(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $net = $this->network('Office', 1, '10.10.0.0/24');
        set_user_default_networks((int)$user['id'], [(int)$net['id']]);
        delete_user((int)$user['id']);
        $this->assertSame(0, (int)db()->query('SELECT COUNT(*) FROM user_to_network')->fetchColumn());
    }

    public function testSetupGateFollowsAdminExistence(): void
    {
        $this->assertFalse(admin_exists());
        $this->user('10.0.0.2', 5);
        $this->assertFalse(admin_exists());
        $this->user('10.0.0.1', 15, 'admin');
        $this->assertTrue(admin_exists());
    }

    public function testSingleGrantWithExplicitDurationAndToastText(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $net = $this->network('VPN', 1, '172.16.0.0/24');

        $results = grant_networks($user, [$net], 'extended', 2 * 3600);
        $this->assertSame('02:00:00', $this->router->entries[0]['timeout']);
        $this->assertSame('PANAG ext: VPN', $this->router->entries[0]['comment']);
        $this->assertEqualsWithDelta(time() + 7200, $results[0]['expires_at'], 2);
        $this->assertSame('VPN granted until ' . date('H:i', $results[0]['expires_at']) . '.', single_grant_message($results[0]));

        // A shorter re-grant keeps the longer entry and says so.
        $results = grant_networks($user, [$net], 'extended');
        $this->assertSame('unchanged', $results[0]['action']);
        $this->assertStringContainsString('already active until', single_grant_message($results[0]));
        $this->assertSame('02:00:00', $this->router->entries[0]['timeout']);

        $this->router->failing = true;
        $failed = grant_networks($user, [$net], 'extended');
        $this->assertSame('VPN could not be granted: HTTP 500 (API code 500)', single_grant_message($failed[0]));
    }

    public function testLastAdminCannotBeRemovedOrDemoted(): void
    {
        $admin = $this->user('10.0.0.1', 15, 'admin');
        $this->assertTrue(would_remove_last_admin($admin, null));
        $this->assertTrue(would_remove_last_admin($admin, 'superuser'));
        $this->assertFalse(would_remove_last_admin($admin, 'admin'));

        $this->user('10.0.0.5', 15, 'admin');
        $this->assertFalse(would_remove_last_admin($admin, null));
        $this->assertFalse(would_remove_last_admin($this->user('10.0.0.2', 5), null));
    }

    public function testImportAcceptsLegacyIsadminExports(): void
    {
        require_once __DIR__ . '/../../src/backup.php';
        $json = json_encode([
            ['username' => 'Old Admin', 'user_ip' => '10.8.0.2', 'otp_secret' => 'JBSWY3DPEHPK3PXP', 'isadmin' => 1, 'accesslevel' => 15],
            ['username' => 'Old User', 'user_ip' => '10.8.0.3', 'otp_secret' => 'JBSWY3DPEHPK3PXP', 'isadmin' => 0, 'accesslevel' => 3],
            ['username' => 'New Super', 'user_ip' => '10.8.0.4', 'otp_secret' => 'JBSWY3DPEHPK3PXP', 'role' => 'superuser', 'accesslevel' => 8, 'extended_duration_sec' => 1800],
        ]);
        $result = import_users_json($json);
        $this->assertSame(3, $result['imported']);
        $this->assertSame('admin', fetch_user_by_user_ip('10.8.0.2')['role']);
        $this->assertSame('user', fetch_user_by_user_ip('10.8.0.3')['role']);
        $super = fetch_user_by_user_ip('10.8.0.4');
        $this->assertSame('superuser', $super['role']);
        $this->assertSame(1800, (int)$super['extended_duration_sec']);

        $roundTrip = json_decode(export_users_json(), true);
        $this->assertSame('superuser', $roundTrip[array_search('10.8.0.4', array_column($roundTrip, 'user_ip'), true)]['role']);
    }
}
