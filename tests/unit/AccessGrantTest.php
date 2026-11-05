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

    private function user(string $ip, int $level, int $admin = 0): array
    {
        save_user(null, 'User ' . $ip, $ip, 'JBSWY3DPEHPK3PXP', $admin, $level);
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

        $results = apply_networks_to_user($user, [$low, $high], '01:00:00');

        $this->assertTrue($results[0]['success']);
        $this->assertFalse($results[1]['success']);
        $this->assertSame('Insufficient access level', $results[1]['message']);
        $this->assertCount(1, $this->router->entries);
        $this->assertSame('Whitelist 10.0.0.2', $this->router->entries[0]['list']);
        $this->assertSame('10.10.0.0/24', $this->router->entries[0]['address']);
        $this->assertSame('01:00:00', $this->router->entries[0]['timeout']);
    }

    public function testGrantSkipsAlreadyPresentEntries(): void
    {
        $user = $this->user('10.0.0.2', 5);
        $net = $this->network('Office', 1, '10.10.0.0/24');
        apply_networks_to_user($user, [$net]);
        $results = apply_networks_to_user($user, [$net]);
        $this->assertSame('Already present', $results[0]['message']);
        $this->assertCount(1, $this->router->entries);
    }

    public function testRevokeRemovesOnlyOwnList(): void
    {
        $a = $this->user('10.0.0.2', 5);
        $b = $this->user('10.0.0.3', 5);
        $net = $this->network('Office', 1, '10.10.0.0/24');
        apply_networks_to_user($a, [$net]);
        apply_networks_to_user($b, [$net]);

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
        $results = apply_networks_to_user($user, [$net]);
        $this->assertFalse($results[0]['success']);
        $this->assertSame(500, $results[0]['status']);
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
        $this->user('10.0.0.1', 15, 1);
        $this->assertTrue(admin_exists());
    }
}
