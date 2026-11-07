<?php
use PHPUnit\Framework\TestCase;

final class ValidationTest extends TestCase
{
    protected function setUp(): void
    {
        db()->exec('DELETE FROM users');
    }

    public function testNetworkAddresses(): void
    {
        foreach (['10.0.0.0/24', '10.0.0.5', '0.0.0.0/0', '192.168.1.1/32'] as $ok) {
            $this->assertTrue(is_valid_ipv4_cidr($ok), $ok);
        }
        foreach (['', '10.0.0.0/33', '10.0.0/24', '10.0.0.0/', 'fe80::/64', '10.0.0.0/2a', '300.0.0.0/8'] as $bad) {
            $this->assertFalse(is_valid_ipv4_cidr($bad), $bad);
        }
        $this->assertSame([], validate_network_input('VPN', '172.16.0.0/24'));
        $this->assertCount(2, validate_network_input('', 'nope'));
    }

    public function testNetworkImportValidatesAddresses(): void
    {
        require_once __DIR__ . '/../../src/backup.php';
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('(index 1)');
        import_networks_json((string)json_encode([
            ['name' => 'Ok', 'address' => '10.0.0.0/24', 'accesslevel' => 1],
            ['name' => 'Broken', 'address' => '10.0.0.0/', 'accesslevel' => 1],
        ]), false);
    }

    public function testUserAccounts(): void
    {
        save_user(null, 'Alice', '10.0.0.2', 'JBSWY3DPEHPK3PXP', 'user', 5);
        $alice = fetch_user_by_user_ip('10.0.0.2');

        $this->assertSame([], validate_user_account(null, 'Bob', '10.0.0.3'));
        $this->assertSame([], validate_user_account((int)$alice['id'], 'Alice', '10.0.0.2'), 'own IP is fine');
        $this->assertSame(['User IP 10.0.0.2 is already used by Alice.'], validate_user_account(null, 'Bob', '10.0.0.2'));
        $this->assertCount(2, validate_user_account(null, '', '10.0.0'));
    }

    public function testOtpSecrets(): void
    {
        $this->assertTrue(is_valid_otp_secret('JBSWY3DPEHPK3PXP'));
        $this->assertTrue(is_valid_otp_secret(generate_otp_secret()));
        $this->assertFalse(is_valid_otp_secret('jbswy3dpehpk3pxp'), 'callers upper-case first');
        $this->assertFalse(is_valid_otp_secret('JBSWY3DP'), 'too short');
        $this->assertFalse(is_valid_otp_secret('JBSWY3DPEHPK3PX1'), '1 is not Base32');

        $uri = otp_provisioning_uri(['user_ip' => '10.0.0.2', 'otp_secret' => 'JBSWY3DPEHPK3PXP']);
        $this->assertSame('otpauth://totp/' . rawurlencode(OTP_ISSUER . ':10.0.0.2') . '?secret=JBSWY3DPEHPK3PXP&issuer=' . rawurlencode(OTP_ISSUER) . '&digits=6&period=30', $uri);
    }

    public function testAuditLogSortIsWhitelisted(): void
    {
        $this->assertSame(['key' => 'time', 'dir' => 'desc', 'sql' => 'ORDER BY created_at DESC, id DESC'], audit_log_order(null, null));
        $this->assertSame('ORDER BY action COLLATE NOCASE ASC, id ASC', audit_log_order('action', null)['sql']);
        $this->assertSame('ORDER BY username COLLATE NOCASE DESC, id DESC', audit_log_order('user', 'DESC')['sql']);
        $injected = audit_log_order('id; DROP TABLE users', 'asc; --');
        $this->assertSame('time', $injected['key']);
        $this->assertSame('ORDER BY created_at DESC, id DESC', $injected['sql']);
    }
}
