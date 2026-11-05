<?php
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class IpInCidrTest extends TestCase
{
    public static function cases(): array
    {
        return [
            ['10.1.2.3', '10.0.0.0/8', true],
            ['11.1.2.3', '10.0.0.0/8', false],
            ['172.31.255.255', '172.16.0.0/12', true],
            ['172.32.0.0', '172.16.0.0/12', false],
            ['192.168.1.1', '192.168.1.1', true],
            ['192.168.1.2', '192.168.1.1', false],
            ['1.2.3.4', '0.0.0.0/0', true],
            ['10.0.0.1', '10.0.0.1/32', true],
            ['10.0.0.1', '10.0.0.0/33', false],
            ['10.0.0.1', '10.0.0.0/abc', false],
            ['not-an-ip', '10.0.0.0/8', false],
            ['::1', '10.0.0.0/8', false],
        ];
    }

    #[DataProvider('cases')]
    public function testIpInCidr(string $ip, string $cidr, bool $expected): void
    {
        $this->assertSame($expected, ip_in_cidr($ip, $cidr));
    }

    public function testLoginWhitelist(): void
    {
        $this->assertTrue(ip_in_any_cidr('10.0.0.2', ['192.168.0.0/16', '10.0.0.0/8']));
        $this->assertFalse(ip_in_any_cidr('8.8.8.8', ['192.168.0.0/16', '10.0.0.0/8']));
    }
}
