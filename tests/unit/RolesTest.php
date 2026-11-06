<?php
use PHPUnit\Framework\TestCase;

final class RolesTest extends TestCase
{
    public function testPermissionMatrix(): void
    {
        $user = ['role' => 'user'];
        $super = ['role' => 'superuser'];
        $admin = ['role' => 'admin'];

        foreach ([$user, $super, $admin] as $u) {
            $this->assertTrue(can($u, 'grant_access'));
            $this->assertTrue(can($u, 'edit_own_preferences'));
        }
        $this->assertFalse(can($user, 'edit_own_default_networks'));
        $this->assertTrue(can($super, 'edit_own_default_networks'));
        $this->assertTrue(can($admin, 'edit_own_default_networks'));

        foreach (['admin', 'manage_users', 'manage_networks', 'revoke_others', 'impersonate', 'view_logs', 'view_status', 'view_config'] as $perm) {
            $this->assertFalse(can($user, $perm), $perm);
            $this->assertFalse(can($super, $perm), $perm);
            $this->assertTrue(can($admin, $perm), $perm);
        }
    }

    public function testUnknownOrMissingRoleHasNoPermissions(): void
    {
        $this->assertFalse(can(null, 'grant_access'));
        $this->assertFalse(can(['role' => 'root'], 'admin'));
        $this->assertFalse(can([], 'grant_access'));
    }

    public function testUnknownPermissionIsAProgrammingError(): void
    {
        $this->expectException(InvalidArgumentException::class);
        can(['role' => 'admin'], 'does_not_exist');
    }
}
