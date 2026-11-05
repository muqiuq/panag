<?php
use PHPUnit\Framework\TestCase;

final class ClientIpTest extends TestCase
{
    private const PROXIES = ['10.89.0.0/16'];

    public function testUsesRemoteAddrWithoutTrustedProxies(): void
    {
        $server = ['REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4'];
        $this->assertSame('10.0.0.5', resolve_client_ip($server, [], [], false));
    }

    public function testIgnoresForwardedForFromUntrustedPeer(): void
    {
        $server = ['REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '127.0.0.1'];
        $this->assertSame('10.0.0.5', resolve_client_ip($server, [], self::PROXIES, false));
    }

    public function testUsesForwardedForFromTrustedProxy(): void
    {
        $server = ['REMOTE_ADDR' => '10.89.0.7', 'HTTP_X_FORWARDED_FOR' => '10.0.0.2'];
        $this->assertSame('10.0.0.2', resolve_client_ip($server, [], self::PROXIES, false));
    }

    public function testWalksChainRightToLeftSkippingTrustedHops(): void
    {
        // client spoofs 127.0.0.1, real client is 10.0.0.2, then two trusted proxies
        $server = ['REMOTE_ADDR' => '10.89.0.7', 'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 10.0.0.2, 10.89.0.9'];
        $this->assertSame('10.0.0.2', resolve_client_ip($server, [], self::PROXIES, false));
    }

    public function testMalformedChainFallsBackToRemoteAddr(): void
    {
        $server = ['REMOTE_ADDR' => '10.89.0.7', 'HTTP_X_FORWARDED_FOR' => 'garbage'];
        $this->assertSame('10.89.0.7', resolve_client_ip($server, [], self::PROXIES, false));
    }

    public function testDevCookieIgnoredOutsideDevMode(): void
    {
        $server = ['REMOTE_ADDR' => '10.0.0.5'];
        $cookies = [DEV_IP_COOKIE => '127.0.0.1'];
        $this->assertSame('10.0.0.5', resolve_client_ip($server, $cookies, [], false, '127.0.0.1'));
    }

    public function testDevCookieAndDefaultInDevMode(): void
    {
        $server = ['REMOTE_ADDR' => '10.88.0.1'];
        $this->assertSame('10.0.0.2', resolve_client_ip($server, [DEV_IP_COOKIE => '10.0.0.2'], [], true, '127.0.0.1'));
        $this->assertSame('127.0.0.1', resolve_client_ip($server, [], [], true, '127.0.0.1'));
        $this->assertSame('127.0.0.1', resolve_client_ip($server, [DEV_IP_COOKIE => 'nope'], [], true, '127.0.0.1'));
    }

    public function testTrustedForwardedForBeatsDevDefault(): void
    {
        $server = ['REMOTE_ADDR' => '10.89.0.7', 'HTTP_X_FORWARDED_FOR' => '10.0.0.9'];
        $this->assertSame('10.0.0.9', resolve_client_ip($server, [], self::PROXIES, true, '127.0.0.1'));
    }
}
